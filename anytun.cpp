/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <iostream>
#include <poll.h>

#include <gcrypt.h>   // for thread safe libgcrypt initialisation
#include <cerrno>     // for ENOMEM

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cypher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "authTag.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"

#include "syncQueue.h"
#include "syncSocketHandler.h"
#include "syncListenSocket.h"

#include "syncSocket.h"
#include "syncClientSocket.h"
#include "syncCommand.h"

#include "threadParam.h"

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0800

#define SESSION_KEYLEN_AUTH 20
#define SESSION_KEYLEN_ENCR 16
#define SESSION_KEYLEN_SALT 14

uint8_t key[] = {
 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
 'q', 'r', 's', 't'
};

uint8_t salt[] = {
 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
 'i', 'j', 'k', 'l', 'm', 'n'
};

void createConnection(const std::string & remote_host , u_int16_t remote_port, ConnectionList & cl, u_int16_t seqSize, SyncQueue & queue)
{

	SeqWindow * seq= new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = new KeyDerivation;
  kd->init(Buffer(key, sizeof(key)), Buffer(salt, sizeof(salt)));
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_host << ":" << remote_port;
	ConnectionParam connparam ( (*kd),  (*seq), seq_nr_, remote_host,  remote_port);
	cl.addConnection(connparam,0);
	SyncCommand sc (cl,0);
	queue.push(sc);
}


void addPacketAuthTag(EncryptedPacket& pack, AuthAlgo& a, ConnectionParam& conn)
{
  AuthTag at = a.calc(pack);
  pack.setAuthTag( at );
}

bool checkPacketAuthTag(EncryptedPacket& pack, AuthAlgo& a, ConnectionParam & conn)
{
  // check auth_tag and remove it
  AuthTag at = pack.getAuthTag();
  return (at == a.calc(pack));
}

bool checkPacketSeqNr(EncryptedPacket& pack,ConnectionParam& conn)
{
	// compare sender_id and seq with window
	if(conn.seq_window_.hasSeqNr(pack.getSenderId(), pack.getSeqNr()))
	{
		cLog.msg(Log::PRIO_NOTICE) << "Replay attack from " << conn.remote_host_<<":"<< conn.remote_port_<< " seq:"<<pack.getSeqNr() << " sid: "<<pack.getSenderId();
		return false;
	}

	conn.seq_window_.addSeqNr(pack.getSenderId(), pack.getSeqNr());
	return true;
}

void* sender(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);
	//TODO make Cypher selectable with command line option
  AesIcmCypher c;
  Sha1AuthAlgo a;

  //TODO make pack global, reduce dynamic memory!
  PlainPacket plain_packet(1600); // TODO: fix me... mtu size
  EncryptedPacket packet(1600);

  Buffer session_key(SESSION_KEYLEN_ENCR), session_salt(SESSION_KEYLEN_SALT), session_auth_key(SESSION_KEYLEN_AUTH);

  //TODO replace mux
  u_int16_t mux = 0;
  while(1)
  {
    packet.setLength( packet.getSize() );
    plain_packet.setLength( plain_packet.getSize() );

    // read packet from device
    u_int32_t len = param->dev.read(plain_packet);
    plain_packet.setLength(len);

    if( param->cl.empty())
      continue;
		ConnectionMap::iterator cit = param->cl.getConnection(mux);
		if(cit==param->cl.getEnd())
			continue;
		ConnectionParam & conn = cit->second;

    // add payload type
    if(param->dev.getType() == TunDevice::TYPE_TUN)
      plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
    else if(param->dev.getType() == TunDevice::TYPE_TAP)
      plain_packet.setPayloadType(PAYLOAD_TYPE_TAP);
    else 
      plain_packet.setPayloadType(0);

    // encrypt packet
    conn.kd_.generate(LABEL_SATP_ENCRYPTION, conn.seq_nr_, session_key, session_key.getLength());
    conn.kd_.generate(LABEL_SATP_SALT, conn.seq_nr_, session_salt, session_salt.getLength());
    conn.kd_.generate(LABEL_SATP_MSG_AUTH, packet.getSeqNr(), session_auth_key, session_auth_key.getLength());
    
    c.setKey(session_key);
    c.setSalt(session_salt);
    c.cypher(packet, plain_packet, plain_packet.getLength(), conn.seq_nr_, param->opt.getSenderId());

    packet.setHeader(conn.seq_nr_, param->opt.getSenderId(), mux);
    conn.seq_nr_++;

    a.setKey(session_auth_key);
		addPacketAuthTag(packet, a, conn);
    param->src.send(packet, conn.remote_host_, conn.remote_port_);
  }
  pthread_exit(NULL);
}

void* syncConnector(void* p )
{
	ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

	SocketHandler h;
	SyncClientSocket sock(h,param->cl);
	//	sock.EnableSSL();
	sock.Open( param->connto.host, param->connto.port);
	h.Add(&sock);
	while (h.GetCount())
	{
		h.Select();
	}
  pthread_exit(NULL);
}

void* syncListener(void* p )
{
	ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

	SyncSocketHandler h(param->queue);
	SyncListenSocket<SyncSocket,ConnectionList> l(h,param->cl);

	if (l.Bind(param->opt.getLocalSyncPort()))
		pthread_exit(NULL);
	Utility::ResolveLocal(); // resolve local hostname
	h.Add(&l);
	h.Select(1,0);
	while (1)
	{
		h.Select(1,0);
	}
}

void* receiver(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);  
  AesIcmCypher c;
  Sha1AuthAlgo a;

  EncryptedPacket packet(1600);     // TODO: dynamic mtu size
  PlainPacket plain_packet(1600);
  Buffer session_key(SESSION_KEYLEN_SALT), session_salt(SESSION_KEYLEN_SALT), session_auth_key(SESSION_KEYLEN_AUTH);

  while(1)
  {
    string remote_host;
    u_int16_t remote_port;
    packet.setLength( packet.getSize() );
    plain_packet.setLength( plain_packet.getSize() );
    //    u_int16_t sid = 0, seq = 0;

    // read packet from socket
    u_int32_t len = param->src.recv(packet, remote_host, remote_port);
    packet.setLength(len);

    // autodetect peer
		// TODO check auth tag first
		// this should be done by keymanagement anyway
    if(param->opt.getRemoteAddr() == "" && param->cl.empty())
		{
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_host << ":" << remote_port;
			createConnection(remote_host, remote_port, param->cl,param->opt.getSeqWindowSize(),param->queue);
		}

		//TODO Add multi connection support here
		ConnectionParam & conn = param->cl.getConnection(0)->second;

    conn.kd_.generate(LABEL_SATP_MSG_AUTH, packet.getSeqNr(), session_auth_key, session_auth_key.getLength());
    a.setKey( session_auth_key );
		if(!checkPacketAuthTag(packet, a, conn))
			continue;

		//Allow dynamic IP changes 
		//TODO add command line option to turn this off
		if (remote_host != conn.remote_host_ || remote_port != conn.remote_port_)
		{
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host ip changed " << remote_host << ":" << remote_port;
			conn.remote_host_=remote_host;
			conn.remote_port_=remote_port;
			SyncCommand sc (param->cl,0);
			param->queue.push(sc);
		}	

		// Replay Protection
		if (!checkPacketSeqNr(packet, conn))
			continue;

    // decrypt packet
    conn.kd_.generate(LABEL_SATP_ENCRYPTION, packet.getSeqNr(), session_key, session_key.getLength());
    conn.kd_.generate(LABEL_SATP_SALT, packet.getSeqNr(), session_salt, session_salt.getLength());
    c.setKey(session_key);
    c.setSalt(session_salt);
    c.cypher(plain_packet, packet, packet.getLength(), packet.getSeqNr(), packet.getSenderId());
    
    // check payload_type and remove it
    if((param->dev.getType() == TunDevice::TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN) ||
       (param->dev.getType() == TunDevice::TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP))
      continue;

    // write it on the device
    param->dev.write(plain_packet);
  }
  pthread_exit(NULL);
}



extern "C" {
GCRY_THREAD_OPTION_PTHREAD_IMPL;
}

int main(int argc, char* argv[])
{
  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;
  Options opt;
  if(!opt.parse(argc, argv))
  {
    opt.printUsage();
    exit(-1);
  }
  cLog.msg(Log::PRIO_NOTICE) << "anytun started...";

  SignalController sig;
  sig.init();
  std::string dev_type(opt.getDevType()); 
  TunDevice dev(opt.getDevName().c_str(), dev_type=="" ? NULL : dev_type.c_str(), opt.getIfconfigParamLocal().c_str(), opt.getIfconfigParamRemoteNetmask().c_str());

  PacketSource* src;
  if(opt.getLocalAddr() == "")
    src = new UDPPacketSource(opt.getLocalPort());
  else
    src = new UDPPacketSource(opt.getLocalAddr(), opt.getLocalPort());

	ConnectionList cl;
	ConnectToList connect_to = opt.getConnectTo();
	SyncQueue queue;

	if(opt.getRemoteAddr() != "")
		createConnection(opt.getRemoteAddr(),opt.getRemotePort(),cl,opt.getSeqWindowSize(), queue);
  

  ThreadParam p(opt, dev, *src, cl, queue,*(new OptionConnectTo()));
    
  cLog.msg(Log::PRIO_NOTICE) << "dev created (opened)";
  cLog.msg(Log::PRIO_NOTICE) << "dev opened - actual name is '" << p.dev.getActualName() << "'";
  cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << p.dev.getTypeString() << "'";

  gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread );

  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, &p);  
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &p);  
	pthread_t syncListenerThread;

	if ( opt.getLocalSyncPort())
		pthread_create(&syncListenerThread, NULL, syncListener, &p);  

	std::list<pthread_t> connectThreads;
	for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it) 
	{ 
	 connectThreads.push_back(pthread_t());
	 ThreadParam * point = new ThreadParam(opt, dev, *src, cl, queue,*it);
	 pthread_create(& connectThreads.back(),  NULL, syncConnector, point);
	}
  
	int ret = sig.run();

  pthread_cancel(senderThread);
  pthread_cancel(receiverThread);  
	if ( opt.getLocalSyncPort())
	  pthread_cancel(syncListenerThread);  
	for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
		pthread_cancel(*it);

  pthread_join(senderThread, NULL);
  pthread_join(receiverThread, NULL);
	if ( opt.getLocalSyncPort())
	  pthread_join(syncListenerThread, NULL);

	for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
	  pthread_join(*it, NULL);

  delete src;
	delete &p.connto;

  return ret;
}

