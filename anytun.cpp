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
#include <cerrno>     // for ENOMEM

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cipher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "authTag.h"
#include "cipherFactory.h"
#include "authAlgoFactory.h"
#include "keyDerivationFactory.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"

#include "syncQueue.h"
#include "syncSocketHandler.h"
#include "syncListenSocket.h"

#include "syncSocket.h"
#include "syncClientSocket.h"
#include "syncCommand.h"

#include "threadParam.h"

#define MAX_PACKET_LENGTH 1600

#define SESSION_KEYLEN_AUTH 20   // TODO: hardcoded size
#define SESSION_KEYLEN_ENCR 16   // TODO: hardcoded size
#define SESSION_KEYLEN_SALT 14   // TODO: hardcoded size

void createConnection(const std::string & remote_host, u_int16_t remote_port, ConnectionList & cl, u_int16_t seqSize, SyncQueue & queue, mux_t mux)
{
	SeqWindow * seq= new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_host << ":" << remote_port;
	ConnectionParam connparam ( (*kd),  (*seq), seq_nr_, remote_host,  remote_port);
 	cl.addConnection(connparam,mux);
	NetworkAddress addr(ipv4,gOpt.getIfconfigParamRemoteNetmask().c_str());
	NetworkPrefix prefix(addr,32);
	gRoutingTable.addRoute(prefix,mux);
  SyncCommand sc (cl,mux);
	queue.push(sc);
  SyncCommand sc2 (prefix);
	queue.push(sc2);
}


void addPacketAuthTag(EncryptedPacket& pack, AuthAlgo* a, ConnectionParam& conn)
{
  AuthTag at = a->calc(pack);
  pack.setAuthTag( at );
}

bool checkPacketAuthTag(EncryptedPacket& pack, AuthAlgo* a, ConnectionParam & conn)
{
  // check auth_tag and remove it
  AuthTag at = pack.getAuthTag();
  return (at == a->calc(pack));
}

bool checkPacketSeqNr(EncryptedPacket& pack,ConnectionParam& conn)
{
	// compare sender_id and seq with window
	if(conn.seq_window_.hasSeqNr(pack.getSenderId(), pack.getSeqNr()))
	{
		cLog.msg(Log::PRIO_NOTICE) << "Replay attack from " << conn.remote_host_<<":"<< conn.remote_port_ 
                               << " seq:"<<pack.getSeqNr() << " sid: "<<pack.getSenderId();
		return false;
	}
  
	conn.seq_window_.addSeqNr(pack.getSenderId(), pack.getSeqNr());
	return true;
}

void* sender(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

  std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher()));
//  std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo()) );

  PlainPacket plain_packet(MAX_PACKET_LENGTH);
  EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);

  Buffer session_key(u_int32_t(SESSION_KEYLEN_ENCR));             // TODO: hardcoded size
  Buffer session_salt(u_int32_t(SESSION_KEYLEN_SALT));            // TODO: hardcoded size
  Buffer session_auth_key(u_int32_t(SESSION_KEYLEN_AUTH));        // TODO: hardcoded size

  //TODO replace mux
  u_int16_t mux = gOpt.getMux();
  while(1)
  {
    plain_packet.setLength(MAX_PACKET_LENGTH);
    encrypted_packet.setLength(MAX_PACKET_LENGTH);
    // read packet from device
    u_int32_t len = param->dev.read(plain_packet.getPayload(), plain_packet.getPayloadLength());
    plain_packet.setPayloadLength(len);
    // set payload type
    if(param->dev.getType() == TunDevice::TYPE_TUN)
      plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
    else if(param->dev.getType() == TunDevice::TYPE_TAP)
      plain_packet.setPayloadType(PAYLOAD_TYPE_TAP);
    else 
      plain_packet.setPayloadType(0);

    if(param->cl.empty())
      continue;
		//std::cout << "got Packet for plain "<<plain_packet.getDstAddr().toString();
		mux = gRoutingTable.getRoute(plain_packet.getDstAddr());
		//std::cout << " -> "<<mux << std::endl;
    ConnectionMap::iterator cit = param->cl.getConnection(mux);
		if(cit==param->cl.getEnd())
			continue;
		ConnectionParam & conn = cit->second;
		
		if(conn.remote_host_==""||!conn.remote_port_)
			continue;
    // generate packet-key
    conn.kd_.generate(LABEL_SATP_ENCRYPTION, conn.seq_nr_, session_key);
    conn.kd_.generate(LABEL_SATP_SALT, conn.seq_nr_, session_salt);

    c->setKey(session_key);
    c->setSalt(session_salt);

    // encrypt packet
    c->encrypt(plain_packet, encrypted_packet, conn.seq_nr_, gOpt.getSenderId());

    encrypted_packet.setHeader(conn.seq_nr_, gOpt.getSenderId(), mux);
    conn.seq_nr_++;

        // TODO: activate authentication
//    conn.kd_.generate(LABEL_SATP_MSG_AUTH, encrypted_packet.getSeqNr(), session_auth_key);
//    a->setKey(session_auth_key);
//		addPacketAuthTag(encrypted_packet, a.get(), conn);

    param->src.send(encrypted_packet.getBuf(), encrypted_packet.getLength(), conn.remote_host_, conn.remote_port_);
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

	if (l.Bind(gOpt.getLocalSyncPort()))
		pthread_exit(NULL);

	Utility::ResolveLocal(); // resolve local hostname
	h.Add(&l);
	h.Select(1,0);
	while (1) {
		h.Select(1,0);
	}
}

void* receiver(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p); 

  std::auto_ptr<Cipher> c( CipherFactory::create(gOpt.getCipher()) );
//  std::auto_ptr<AuthAlgo> a( AuthAlgoFactory::create(gOpt.getAuthAlgo()) );

  EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);
  PlainPacket plain_packet(MAX_PACKET_LENGTH);

  Buffer session_key(u_int32_t(SESSION_KEYLEN_ENCR));             // TODO: hardcoded size
  Buffer session_salt(u_int32_t(SESSION_KEYLEN_SALT));            // TODO: hardcoded size
  Buffer session_auth_key(u_int32_t(SESSION_KEYLEN_AUTH));        // TODO: hardcoded size

  while(1)
  {
    string remote_host;
    u_int16_t remote_port;

    plain_packet.setLength(MAX_PACKET_LENGTH);
    encrypted_packet.setLength(MAX_PACKET_LENGTH);

    // read packet from socket
    u_int32_t len = param->src.recv(encrypted_packet.getBuf(), encrypted_packet.getLength(), remote_host, remote_port);
    encrypted_packet.setLength(len);

		// TODO: check auth tag first
//    conn.kd_.generate(LABEL_SATP_MSG_AUTH, encrypted_packet.getSeqNr(), session_auth_key);
//    a->setKey( session_auth_key );
//		if(!checkPacketAuthTag(encrypted_packet, a.get(), conn))
//			continue;

		mux_t mux = encrypted_packet.getMux();
    // autodetect peer
    if(gOpt.getRemoteAddr() == "" && param->cl.empty())
		{
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_host << ":" << remote_port;
			createConnection(remote_host, remote_port, param->cl, gOpt.getSeqWindowSize(),param->queue,mux);
		}

		ConnectionMap::iterator cit = param->cl.getConnection(mux);
		if (cit == param->cl.getEnd())
			continue;
		ConnectionParam & conn = cit->second;

		//Allow dynamic IP changes 
		//TODO: add command line option to turn this off
		if (remote_host != conn.remote_host_ || remote_port != conn.remote_port_)
		{
      cLog.msg(Log::PRIO_NOTICE) << "connection "<< mux << " autodetected remote host ip changed " << remote_host << ":" << remote_port;
			conn.remote_host_=remote_host;
			conn.remote_port_=remote_port;
			SyncCommand sc (param->cl,mux);
			param->queue.push(sc);
		}	

		// Replay Protection
		if (!checkPacketSeqNr(encrypted_packet, conn))
			continue;
    
    // generate packet-key
    conn.kd_.generate(LABEL_SATP_ENCRYPTION, encrypted_packet.getSeqNr(), session_key);
    conn.kd_.generate(LABEL_SATP_SALT, encrypted_packet.getSeqNr(), session_salt);
    c->setKey(session_key);
    c->setSalt(session_salt);

    // decrypt packet
    c->decrypt(encrypted_packet, plain_packet);
    
    // check payload_type
    if((param->dev.getType() == TunDevice::TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN) ||
       (param->dev.getType() == TunDevice::TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP))
      continue;

    // write it on the device
    param->dev.write(plain_packet.getPayload(), plain_packet.getLength());
  }
  pthread_exit(NULL);
}

#define MIN_GCRYPT_VERSION "1.2.3"
// make libgcrypt thread safe
extern "C" {
GCRY_THREAD_OPTION_PTHREAD_IMPL;
}

bool initLibGCrypt()
{
  // make libgcrypt thread safe 
  // this must be called before any other libgcrypt call
  gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread );

  // this must be called right after the GCRYCTL_SET_THREAD_CBS command
  // no other function must be called till now
  if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
    std::cout << "initLibGCrypt: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION << std::endl;
    return false;
  }
    
  // Tell Libgcrypt that initialization has completed.
  gcry_error_t err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
  if( err ) {
    std::cout << "initLibGCrypt: Failed to finish the initialization of libgcrypt: " << gpg_strerror( err ) << std::endl;
    return false;
  }

  cLog.msg(Log::PRIO_NOTICE) << "initLibGCrypt: libgcrypt init finished";
  return true;
}
 
int main(int argc, char* argv[])
{
  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }
  cLog.msg(Log::PRIO_NOTICE) << "anytun started...";

  SignalController sig;
  sig.init();
  std::string dev_type(gOpt.getDevType()); 
  TunDevice dev(gOpt.getDevName().c_str(), dev_type=="" ? NULL : dev_type.c_str(), gOpt.getIfconfigParamLocal().c_str(), gOpt.getIfconfigParamRemoteNetmask().c_str());

  PacketSource* src;
  if(gOpt.getLocalAddr() == "")
    src = new UDPPacketSource(gOpt.getLocalPort());
  else
    src = new UDPPacketSource(gOpt.getLocalAddr(), gOpt.getLocalPort());

	ConnectionList cl;
	ConnectToList connect_to = gOpt.getConnectTo();
	SyncQueue queue;

	if(gOpt.getRemoteAddr() != "")
		createConnection(gOpt.getRemoteAddr(),gOpt.getRemotePort(),cl,gOpt.getSeqWindowSize(), queue, gOpt.getMux());

  ThreadParam p(dev, *src, cl, queue,*(new OptionConnectTo()));
    
  cLog.msg(Log::PRIO_NOTICE) << "dev created (opened)";
  cLog.msg(Log::PRIO_NOTICE) << "dev opened - actual name is '" << p.dev.getActualName() << "'";
  cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << p.dev.getTypeString() << "'";

  // this must be called before any other libgcrypt call
  if(!initLibGCrypt())
    return -1;

  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, &p);  
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &p);    

	pthread_t syncListenerThread;
	if ( gOpt.getLocalSyncPort())
		pthread_create(&syncListenerThread, NULL, syncListener, &p);  

	std::list<pthread_t> connectThreads;
	for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it) 
	{ 
	 connectThreads.push_back(pthread_t());
	 ThreadParam * point = new ThreadParam(dev, *src, cl, queue,*it);
	 pthread_create(& connectThreads.back(),  NULL, syncConnector, point);
	}
  
	int ret = sig.run();

  pthread_cancel(senderThread);
  pthread_cancel(receiverThread);  
	if ( gOpt.getLocalSyncPort())
	  pthread_cancel(syncListenerThread);  
	for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
		pthread_cancel(*it);
  
  pthread_join(senderThread, NULL);
  pthread_join(receiverThread, NULL);
	if ( gOpt.getLocalSyncPort())
	  pthread_join(syncListenerThread, NULL);

	for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
	  pthread_join(*it, NULL);

  delete src;
	delete &p.connto;

  return ret;
}

