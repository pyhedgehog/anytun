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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>


#include <boost/bind.hpp>
#ifndef NOCRYPT
#include <gcrypt.h>
#endif
#include <cerrno>     // for ENOMEM

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cipher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "cipherFactory.h"
#include "authAlgoFactory.h"
#include "keyDerivationFactory.h"
#ifndef NOSIGNALCONTROLLER
#include "signalController.h"
#endif
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"
#ifndef NOROUTING
#include "routingTable.h"
#include "networkAddress.h"
#endif

#include "syncQueue.h"
#include "syncCommand.h"

#ifndef ANYTUN_NOSYNC
#include "syncServer.h"
#include "syncClient.h"
#include "syncOnConnect.hpp"
#endif

#include "threadParam.h"
#define MAX_PACKET_LENGTH 1600

#include "cryptinit.hpp"
#include "daemon.hpp"
#include "sysexec.hpp"

#define SESSION_KEYLEN_AUTH 20   // TODO: hardcoded size
#define SESSION_KEYLEN_ENCR 16   // TODO: hardcoded size
#define SESSION_KEYLEN_SALT 14   // TODO: hardcoded size

void createConnection(const PacketSourceEndpoint & remote_end, ConnectionList & cl, window_size_t seqSize, SyncQueue & queue, mux_t mux)
{
	SeqWindow * seq= new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;

	ConnectionParam connparam ( (*kd),  (*seq), seq_nr_, remote_end);
 	cl.addConnection(connparam,mux);
  SyncCommand sc (cl,mux);
	queue.push(sc);
#ifndef NOROUTING
	if (gOpt.getIfconfigParamRemoteNetmask() != "")
	{
		NetworkAddress addr(gOpt.getIfconfigParamRemoteNetmask());
		NetworkPrefix prefix(addr,128);
		gRoutingTable.addRoute(prefix,mux);
  	SyncCommand sc2 (prefix);
		queue.push(sc2);
	}
#endif
}

bool checkPacketSeqNr(EncryptedPacket& pack,ConnectionParam& conn)
{
	// compare sender_id and seq with window
	if(conn.seq_window_.hasSeqNr(pack.getSenderId(), pack.getSeqNr()))
	{
		cLog.msg(Log::PRIO_NOTICE) << "Replay attack from " << conn.remote_end_ 
                               << " seq:"<<pack.getSeqNr() << " sid: "<<pack.getSenderId();
		return false;
	}
  
	conn.seq_window_.addSeqNr(pack.getSenderId(), pack.getSeqNr());
	return true;
}

void sender(void* p)
{
  try 
  {
    ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher()));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo()) );
    
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);
    
    Buffer session_key(u_int32_t(SESSION_KEYLEN_ENCR));             // TODO: hardcoded size
    Buffer session_salt(u_int32_t(SESSION_KEYLEN_SALT));            // TODO: hardcoded size
    Buffer session_auth_key(u_int32_t(SESSION_KEYLEN_AUTH));        // TODO: hardcoded size
    
        //TODO replace mux
    u_int16_t mux = gOpt.getMux();
    PacketSourceEndpoint emptyEndpoint;
    while(1)
    {
      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from device
      u_int32_t len = param->dev.read(plain_packet.getPayload(), plain_packet.getPayloadLength());
      plain_packet.setPayloadLength(len);
          // set payload type
      if(param->dev.getType() == TYPE_TUN)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
      else if(param->dev.getType() == TYPE_TAP)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TAP);
      else 
        plain_packet.setPayloadType(0);
      
      if(param->cl.empty())
        continue;
          //std::cout << "got Packet for plain "<<plain_packet.getDstAddr().toString();
#ifndef NOROUTING
      mux = gRoutingTable.getRoute(plain_packet.getDstAddr());
          //std::cout << " -> "<<mux << std::endl;
      ConnectionMap::iterator cit = param->cl.getConnection(mux);
#else
      ConnectionMap::iterator cit = param->cl.getBegin();
#endif

      if(cit==param->cl.getEnd())
        continue;
      ConnectionParam & conn = cit->second;
      
      if(conn.remote_end_ == emptyEndpoint)
			{
        //cLog.msg(Log::PRIO_INFO) << "no remote address set";
        continue;
      }

          // generate packet-key TODO: do this only when needed
      conn.kd_.generate(LABEL_SATP_ENCRYPTION, conn.seq_nr_, session_key);
      conn.kd_.generate(LABEL_SATP_SALT, conn.seq_nr_, session_salt);
      
      c->setKey(session_key);
      c->setSalt(session_salt);
      
          // encrypt packet
      c->encrypt(plain_packet, encrypted_packet, conn.seq_nr_, gOpt.getSenderId(), mux);
      
      encrypted_packet.setHeader(conn.seq_nr_, gOpt.getSenderId(), mux);
      conn.seq_nr_++;
      
          // add authentication tag
      if(a->getMaxLength()) {
        encrypted_packet.addAuthTag();
        conn.kd_.generate(LABEL_SATP_MSG_AUTH, encrypted_packet.getSeqNr(), session_auth_key);
        a->setKey(session_auth_key);
        a->generate(encrypted_packet);
      }  
      try
      {
        param->src.send(encrypted_packet.getBuf(), encrypted_packet.getLength(), conn.remote_end_);
      }
      catch (std::exception& e)
      {
            // ignoring icmp port unreachable :) and other socket errors :(
      }
    }
  }
  catch(std::runtime_error& e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender thread died due to an uncaught exception: " << e.what();
  }
}
  
#ifndef ANYTUN_NOSYNC
void syncConnector(void* p )
{
	ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

	SyncClient sc ( param->connto.host, param->connto.port);
	sc.run();
}

void syncListener(SyncQueue * queue)
{
  try
  {
    boost::asio::io_service io_service;
		SyncTcpConnection::proto::resolver resolver(io_service);
		SyncTcpConnection::proto::endpoint e;
		if(gOpt.getLocalSyncAddr()!="")
		{
			SyncTcpConnection::proto::resolver::query query(gOpt.getLocalSyncAddr(), gOpt.getLocalSyncPort());
			e = *resolver.resolve(query);
		} else {
			SyncTcpConnection::proto::resolver::query query(gOpt.getLocalSyncPort());
			e = *resolver.resolve(query);
		}


    SyncServer server(io_service,e);
		server.onConnect=boost::bind(syncOnConnect,_1);
		queue->setSyncServerPtr(&server);
    io_service.run();
  }
  catch (std::exception& e)
  {
    std::string addr = gOpt.getLocalSyncAddr() == "" ? "*" : gOpt.getLocalSyncAddr();
    cLog.msg(Log::PRIO_ERR) << "sync: cannot bind to " << addr << ":" << gOpt.getLocalSyncPort()
                            << " (" << e.what() << ")" << std::endl;
  }

}
#endif

void receiver(void* p)
{
  try
  {
    ThreadParam* param = reinterpret_cast<ThreadParam*>(p); 
    
    std::auto_ptr<Cipher> c( CipherFactory::create(gOpt.getCipher()) );
    std::auto_ptr<AuthAlgo> a( AuthAlgoFactory::create(gOpt.getAuthAlgo()) );
    
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    
    Buffer session_key(u_int32_t(SESSION_KEYLEN_ENCR));             // TODO: hardcoded size
    Buffer session_salt(u_int32_t(SESSION_KEYLEN_SALT));            // TODO: hardcoded size
    Buffer session_auth_key(u_int32_t(SESSION_KEYLEN_AUTH));        // TODO: hardcoded size
    
    while(1)
    {
      PacketSourceEndpoint remote_end;

      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from socket
      u_int32_t len = param->src.recv(encrypted_packet.getBuf(), encrypted_packet.getLength(), remote_end);
      encrypted_packet.setLength(len);
      
      mux_t mux = encrypted_packet.getMux();
          // autodetect peer
      if( param->cl.empty() && gOpt.getRemoteAddr() == "")
      {
        cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_end;
        createConnection(remote_end, param->cl, gOpt.getSeqWindowSize(),param->queue,mux);
      }
      
      ConnectionMap::iterator cit = param->cl.getConnection(mux);
      if (cit == param->cl.getEnd())
        continue;
      ConnectionParam & conn = cit->second;
      
          // check whether auth tag is ok or not
      if(a->getMaxLength()) {
        encrypted_packet.withAuthTag(true);
        conn.kd_.generate(LABEL_SATP_MSG_AUTH, encrypted_packet.getSeqNr(), session_auth_key);
        a->setKey(session_auth_key);
        if(!a->checkTag(encrypted_packet)) {
          cLog.msg(Log::PRIO_NOTICE) << "wrong Authentication Tag!" << std::endl;
          continue;
        }        
        encrypted_packet.removeAuthTag();
      }  
      
          //Allow dynamic IP changes 
          //TODO: add command line option to turn this off
      if (remote_end != conn.remote_end_)
      {
        cLog.msg(Log::PRIO_NOTICE) << "connection "<< mux << " autodetected remote host ip changed " << remote_end;
        conn.remote_end_=remote_end;
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
      if((param->dev.getType() == TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN4 && 
                                              plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN6) ||
         (param->dev.getType() == TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP))
        continue;
      
          // write it on the device
      param->dev.write(plain_packet.getPayload(), plain_packet.getLength());
    }
  }
  catch(std::runtime_error& e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e)
  {
    cLog.msg(Log::PRIO_ERR) << "receiver thread died due to an uncaught exception: " << e.what();
  }
}

 
int main(int argc, char* argv[])
{
  bool daemonized=false;
  try 
  {
  
//  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;
    if(!gOpt.parse(argc, argv)) {
      gOpt.printUsage();
      exit(-1);
    }

    cLog.msg(Log::PRIO_NOTICE) << "anytun started...";
    
    std::ofstream pidFile;
    if(gOpt.getPidFile() != "") {
      pidFile.open(gOpt.getPidFile().c_str());
      if(!pidFile.is_open()) {
        std::cout << "can't open pid file" << std::endl;
      }
    }
    
    TunDevice dev(gOpt.getDevName(), gOpt.getDevType(), gOpt.getIfconfigParamLocal(), gOpt.getIfconfigParamRemoteNetmask());
    cLog.msg(Log::PRIO_NOTICE) << "dev created (opened)";
    cLog.msg(Log::PRIO_NOTICE) << "dev opened - actual name is '" << dev.getActualName() << "'";
    cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << dev.getTypeString() << "'";
#ifndef NOEXEC
    if(gOpt.getPostUpScript() != "") {
      int postup_ret = execScript(gOpt.getPostUpScript(), dev.getActualName());
      cLog.msg(Log::PRIO_NOTICE) << "post up script '" << gOpt.getPostUpScript() << "' returned " << postup_ret;  
    }
#endif
        
    PacketSource* src;
    if(gOpt.getLocalAddr() == "")
      src = new UDPPacketSource(gOpt.getLocalPort());
    else
      src = new UDPPacketSource(gOpt.getLocalAddr(), gOpt.getLocalPort());

    ConnectionList & cl (gConnectionList);
    ConnectToList connect_to = gOpt.getConnectTo();
    SyncQueue queue;
    
    if(gOpt.getRemoteAddr() != "")
    {
      boost::asio::io_service io_service;
      UDPPacketSource::proto::resolver resolver(io_service);
      UDPPacketSource::proto::resolver::query query(gOpt.getRemoteAddr(), gOpt.getRemotePort());
      UDPPacketSource::proto::endpoint endpoint = *resolver.resolve(query);
      createConnection(endpoint,cl,gOpt.getSeqWindowSize(), queue, gOpt.getMux());
    }    

#ifndef NODAEMON
    if(gOpt.getChroot())
      chrootAndDrop(gOpt.getChrootDir(), gOpt.getUsername());
    if(gOpt.getDaemonize())
    {
      daemonize();
      daemonized = true;
    }

    if(pidFile.is_open()) {
      pid_t pid = getpid();
      pidFile << pid;
      pidFile.close();
    }
#endif

#ifndef NOSIGNALCONTROLLER
    SignalController sig;
    sig.init();
#endif
    
    ThreadParam p(dev, *src, cl, queue,*(new OptionConnectTo()));

#ifndef NOCRYPT
// this must be called before any other libgcrypt call
    if(!initLibGCrypt())
      return -1;
#endif

    boost::thread senderThread(boost::bind(sender,&p));
#ifndef NOSIGNALCONTROLLER
    boost::thread receiverThread(boost::bind(receiver,&p)); 
#endif
#ifndef ANYTUN_NOSYNC
    boost::thread * syncListenerThread;
    if(gOpt.getLocalSyncPort() != "")
      syncListenerThread = new boost::thread(boost::bind(syncListener,&queue));
    
    std::list<boost::thread *> connectThreads;
    for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it) { 
      ThreadParam * point = new ThreadParam(dev, *src, cl, queue,*it);
      connectThreads.push_back(new boost::thread(boost::bind(syncConnector,point)));
    }
#endif

#ifndef NOSIGNALCONTROLLER
    int ret = sig.run();  
    return ret;    
#else
	receiver(&p);
#endif
    // TODO cleanup here!
    /*
    pthread_cancel(senderThread);
    pthread_cancel(receiverThread);  
#ifndef ANYTUN_NOSYNC
    if ( gOpt.getLocalSyncPort())
      pthread_cancel(syncListenerThread);  
    for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
      pthread_cancel(*it);
#endif
    
    pthread_join(senderThread, NULL);
    pthread_join(receiverThread, NULL);
#ifndef ANYTUN_NOSYNC
    if ( gOpt.getLocalSyncPort())
      pthread_join(syncListenerThread, NULL);
    
    for( std::list<pthread_t>::iterator it = connectThreads.begin() ;it != connectThreads.end(); ++it)
      pthread_join(*it, NULL);
#endif
    delete src;
    delete &p.connto;

    return ret;  
    */
  }
  catch(std::runtime_error& e)
  {
    if(daemonized)
      cLog.msg(Log::PRIO_ERR) << "uncaught runtime error, exiting: " << e.what();
    else
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
  }
  catch(std::exception& e)
  {
    if(daemonized)
      cLog.msg(Log::PRIO_ERR) << "uncaught exception, exiting: " << e.what();
    else
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
  }
}
  
  
