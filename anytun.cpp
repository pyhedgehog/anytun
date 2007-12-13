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
#include <gcrypt.h>
#include <cerrno>

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "packet.h"
#include "cypher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
//#include "authTag.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"

#include "Sockets/SocketHandler.h"
#include "syncListenSocket.h"

#include "syncSocket.h"
#include "syncClientSocket.h"

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0800

#define SESSION_KEYLEN_AUTH 20
#define SESSION_KEYLEN_ENCR 16
#define SESSION_KEYLEN_SALT 14

struct Param
{
  Options& opt;
  TunDevice& dev;
  PacketSource& src;
	ConnectionList& cl;
};

uint8_t key[] = {
 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
 'q', 'r', 's', 't'
};

uint8_t salt[] = {
 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
 'i', 'j', 'k', 'l', 'm', 'n'
};

void createConnection(const std::string & remote_host , u_int16_t remote_port, ConnectionList & cl, u_int16_t seqSize)
{

	SeqWindow * seq= new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = new KeyDerivation;
  kd->init(Buffer(key, sizeof(key)), Buffer(salt, sizeof(salt)));
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_host << ":" << remote_port;
	ConnectionParam connparam ( (*kd),  (*seq), seq_nr_, remote_host,  remote_port);
	cl.addConnection(connparam,0);
}


void encryptPacket(Packet & pack, Cypher & c, ConnectionParam & conn, void* p)
{
  Param* param = reinterpret_cast<Param*>(p);
  // cypher the packet
  Buffer session_key(SESSION_KEYLEN_ENCR), session_salt(SESSION_KEYLEN_SALT);
  conn.kd_.generate(LABEL_SATP_ENCRYPTION, conn.seq_nr_, session_key, session_key.getLength());
  conn.kd_.generate(LABEL_SATP_SALT, conn.seq_nr_, session_salt, session_salt.getLength());

  c.setKey(session_key);
  c.setSalt(session_salt);

  cLog.msg(Log::PRIO_NOTICE) << "Send Package: seq: " << conn.seq_nr_ 
                             << ", sID: " << param->opt.getSenderId();
  //cLog.msg(Log::PRIO_NOTICE) << "Package dump: " << pack.getHexDump();

  c.cypher(pack, conn.seq_nr_, param->opt.getSenderId());
}

bool decryptPacket(Packet & pack, Cypher & c, ConnectionParam & conn)
{
  u_int16_t sid = pack.getSenderId();
  u_int16_t seq = pack.getSeqNr();

  pack.removeHeader();

  // decypher the packet
  Buffer session_key(SESSION_KEYLEN_SALT), session_salt(SESSION_KEYLEN_SALT);
  conn.kd_.generate(LABEL_SATP_ENCRYPTION, seq, session_key, session_key.getLength());
  conn.kd_.generate(LABEL_SATP_SALT, seq, session_salt, session_salt.getLength());

  c.setKey(session_key);
  c.setSalt(session_salt);
  c.cypher(pack, seq, sid);

  cLog.msg(Log::PRIO_NOTICE) << "Received Package: seq: " << seq 
                             << ", sID: " << sid;
  //cLog.msg(Log::PRIO_NOTICE) << "Package dump: " << pack.getHexDump();

  return true;
}

void addPacketAuthTag(Packet & pack, Cypher & c, ConnectionParam & conn)
{

//    // calc auth_tag and add it to the packet
//    AuthTag at = a.calc(pack);
//    if(at != AuthTag(0)) {
//      //auth_tag_t at = a.calc(pack);
//      pack.addAuthTag(at);
//    }
//
    // send it out to remote host
}

bool checkPacketAuthTag(Packet & pack, Cypher & c, ConnectionParam & conn)
{
//    // check auth_tag and remove it
//    AuthTag at = pack.getAuthTag();
    pack.removeAuthTag();
  //return at == a.calc(pack);
	return true;
}

bool checkPacketSeqNr(Packet & pack,ConnectionParam & conn)
{
// 	u_int16_t sid = pack.getSenderId();
// 	u_int16_t seq = pack.getSeqNr();
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
  Param* param = reinterpret_cast<Param*>(p);
	//TODO make Cypher selectable with command line option
//	NullCypher c;
  AesIcmCypher c;
//  NullAuthAlgo a;

  while(1)
  {
		//TODO make pack global, reduce dynamic memory!
    Packet pack(1600); // fix me... mtu size
		
    // read packet from device
    int len = param->dev.read(pack);
		//TODO remove, no dynamic memory resizing
    pack.resizeBack(len);

    if( param->cl.empty())
      continue;
		//TODO replace 0 with mux
		ConnectionMap::iterator cit = param->cl.getConnection(0);
		if(cit!=param->cl.getEnd())
			continue;
		ConnectionParam & conn = cit->second;
    // add payload type
    if(param->dev.getType() == TunDevice::TYPE_TUN)
      pack.addPayloadType(PAYLOAD_TYPE_TUN);
    else if(param->dev.getType() == TunDevice::TYPE_TAP)
      pack.addPayloadType(PAYLOAD_TYPE_TAP);
    else 
      pack.addPayloadType(0);

		encryptPacket(pack, c, conn, param);

    pack.addHeader(conn.seq_nr_, param->opt.getSenderId());
    conn.seq_nr_++;

		addPacketAuthTag(pack, c, conn);
    param->src.send(pack, conn.remote_host_, conn.remote_port_);
  }
  pthread_exit(NULL);
}

void* syncConnector(void* p )
{
	Param* param = reinterpret_cast<Param*>(p);

	SocketHandler h;
	SyncClientSocket sock(h,param->cl);
	//	sock.EnableSSL();
	sock.Open( param->opt.getRemoteSyncAddr(), param->opt.getRemoteSyncPort());
	h.Add(&sock);
	while (h.GetCount())
	{
		h.Select();
	}
  pthread_exit(NULL);
}

void* syncListener(void* p )
{
	Param* param = reinterpret_cast<Param*>(p);

	SOCKETS_NAMESPACE::SocketHandler h;
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
  Param* param = reinterpret_cast<Param*>(p);  
//  NullCypher c;
  AesIcmCypher c;
//  NullAuthAlgo a;
  
  while(1)
  {
    string remote_host;
    u_int16_t remote_port;
        //    u_int16_t sid = 0, seq = 0;
    Packet pack(1600);  // fix me... mtu size

    // read packet from socket
    u_int32_t len = param->src.recv(pack, remote_host, remote_port);
    pack.resizeBack(len);
    pack.withPayloadType(true).withHeader(true).withAuthTag(false);


    // autodetect peer
		// TODO check auth tag first
		// this should be done by keymanagement anyway
    if(param->opt.getRemoteAddr() == "" && param->cl.empty())
		{
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_host << ":" << remote_port;
			createConnection(remote_host, remote_port, param->cl,param->opt.getSeqWindowSize());
		}

		//TODO Add multi connection support here
		ConnectionParam & conn = param->cl.getConnection(0)->second;

		if (!checkPacketAuthTag(pack, c, conn))
			continue;

		//Allow dynamic IP changes 
		//TODO add command line option to turn this off
		if (remote_host != conn.remote_host_ || remote_port != conn.remote_port_)
		{
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host ip changed " << remote_host << ":" << remote_port;
			conn.remote_host_=remote_host;
			conn.remote_port_=remote_port;
		}	

		//Replay Protection
		if (!checkPacketSeqNr(pack,conn))
			continue;

		if (!decryptPacket(pack, c, conn))
			continue;
    // check payload_type and remove it
    if((param->dev.getType() == TunDevice::TYPE_TUN && pack.getPayloadType() != PAYLOAD_TYPE_TUN) ||
       (param->dev.getType() == TunDevice::TYPE_TAP && pack.getPayloadType() != PAYLOAD_TYPE_TAP))
      continue;
    pack.removePayloadType();
    
    // write it on the device
    param->dev.write(pack);
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

	if(opt.getRemoteAddr() != "")
		createConnection(opt.getRemoteAddr(),opt.getRemotePort(),cl,opt.getSeqWindowSize());
  

  struct Param p = {opt, dev, *src, cl};
    
  cLog.msg(Log::PRIO_NOTICE) << "dev created (opened)";
  cLog.msg(Log::PRIO_NOTICE) << "dev opened - actual name is '" << p.dev.getActualName() << "'";
  cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << p.dev.getTypeString() << "'";

  gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread );

  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, &p);  
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &p);  
	pthread_t syncListenerThread;
	pthread_t syncConnectorThread;
	if ( opt.getLocalSyncPort())
		pthread_create(&syncListenerThread, NULL, syncListener, &p);  
	if ( opt.getRemoteSyncPort() && opt.getRemoteSyncAddr() != "")
		pthread_create(&syncConnectorThread, NULL, syncConnector, &p);  

  int ret = sig.run();

  pthread_cancel(senderThread);
  pthread_cancel(receiverThread);  
	if ( opt.getLocalSyncPort())
	  pthread_cancel(syncListenerThread);  
	if ( opt.getRemoteSyncPort() && opt.getRemoteSyncAddr() != "")
	  pthread_cancel(syncConnectorThread);  
  pthread_join(senderThread, NULL);
  pthread_join(receiverThread, NULL);
	if ( opt.getLocalSyncPort())
	  pthread_join(syncListenerThread, NULL);
	if ( opt.getRemoteSyncPort() && opt.getRemoteSyncAddr() != "")
	  pthread_join(syncConnectorThread, NULL);

  delete src;

  return ret;
}

