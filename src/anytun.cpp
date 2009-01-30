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
#ifndef NO_SIGNALCONTROLLER
#include "signalController.h"
#endif
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"
#ifndef NO_ROUTING
#include "routingTable.h"
#include "networkAddress.h"
#endif


#ifndef ANYTUN_NOSYNC
#include "syncQueue.h"
#include "syncCommand.h"
#include "syncServer.h"
#include "syncClient.h"
#include "syncOnConnect.hpp"
#endif

#include "threadParam.h"
#define MAX_PACKET_LENGTH 1600

#include "cryptinit.hpp"
#include "daemon.hpp"
#include "sysexec.hpp"

void createConnection(const PacketSourceEndpoint & remote_end, window_size_t seqSize, mux_t mux)
{
	SeqWindow* seq = new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt(), gOpt.getPassphrase());
  kd->setLogKDRate(gOpt.getLdKdr());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;

	ConnectionParam connparam ((*kd), (*seq), seq_nr_, remote_end);
 	gConnectionList.addConnection(connparam,mux);
#ifndef ANYTUN_NOSYNC
  SyncCommand sc (gConnectionList,mux);
	gSyncQueue.push(sc);
#endif
#ifndef NO_ROUTING
	if (gOpt.getIfconfigParamRemoteNetmask() != "")
	{
		NetworkAddress addr(gOpt.getIfconfigParamRemoteNetmask());
		NetworkPrefix prefix(addr,128);
		gRoutingTable.addRoute(prefix,mux);
#ifndef ANYTUN_NOSYNC
		SyncCommand sc2 (prefix);
		gSyncQueue.push(sc2);
#endif
	}
#endif
}

#ifndef ANYTUN_NOSYNC
void syncConnector(void* p )
{
	ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

	SyncClient sc ( param->connto.addr, param->connto.port);
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

void sender(void* p)
{
  try 
  {
    ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_OUTBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_OUTBOUND) );
    
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);
    
    u_int16_t mux = gOpt.getMux();
    PacketSourceEndpoint emptyEndpoint;
    while(1) {
      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from device
      int len = param->dev.read(plain_packet.getPayload(), plain_packet.getPayloadLength());
      if(len < 0)
        continue; // silently ignore device read errors, this is probably no good idea...

      if(static_cast<u_int32_t>(len) < PlainPacket::getHeaderLength())
        continue; // ignore short packets
      plain_packet.setPayloadLength(len);
          // set payload type
      if(param->dev.getType() == TYPE_TUN)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
      else if(param->dev.getType() == TYPE_TAP)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TAP);
      else 
        plain_packet.setPayloadType(0);
      
      if(gConnectionList.empty())
        continue;
          //std::cout << "got Packet for plain "<<plain_packet.getDstAddr().toString();
			ConnectionMap::iterator cit;
#ifndef NO_ROUTING
			try {
				mux = gRoutingTable.getRoute(plain_packet.getDstAddr());
						//std::cout << " -> "<<mux << std::endl;
				cit = gConnectionList.getConnection(mux);
			} catch (std::exception& e) { continue; } // no route
#else
      cit = gConnectionList.getBegin();
#endif

      if(cit==gConnectionList.getEnd())
        continue; //no connection
      ConnectionParam & conn = cit->second;
      
      if(conn.remote_end_ == emptyEndpoint) {
        //cLog.msg(Log::PRIO_INFO) << "no remote address set";
        continue;
      }

          // encrypt packet
      c->encrypt(conn.kd_, plain_packet, encrypted_packet, conn.seq_nr_, gOpt.getSenderId(), mux);
      
      encrypted_packet.setHeader(conn.seq_nr_, gOpt.getSenderId(), mux);
      conn.seq_nr_++;
      
          // add authentication tag
      a->generate(conn.kd_, encrypted_packet);

      try {
        param->src.send(encrypted_packet.getBuf(), encrypted_packet.getLength(), conn.remote_end_);
      } catch (std::exception& e) { } // ignoring icmp port unreachable :) and other socket errors :(
    }
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERR) << "sender thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERR) << "sender thread died due to an uncaught exception: " << e.what();
  }
}

void receiver(void* p)
{
  try 
  {
    ThreadParam* param = reinterpret_cast<ThreadParam*>(p); 
    
    std::auto_ptr<Cipher> c( CipherFactory::create(gOpt.getCipher(), KD_INBOUND) );
    std::auto_ptr<AuthAlgo> a( AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_INBOUND) );
    
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH);
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    
    while(1) {
      PacketSourceEndpoint remote_end;

      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from socket
      int len;
      try {
        len = param->src.recv(encrypted_packet.getBuf(), encrypted_packet.getLength(), remote_end);
      } catch (std::exception& e) { continue; }
          // ignoring icmp port unreachable :) and other socket errors :(
      if(len < 0)
        continue; // silently ignore socket recv errors, this is probably no good idea...

      if(static_cast<u_int32_t>(len) < EncryptedPacket::getHeaderLength())
        continue; // ignore short packets
      encrypted_packet.setLength(len);
      
      mux_t mux = encrypted_packet.getMux();
          // autodetect peer
      if( gConnectionList.empty() && gOpt.getRemoteAddr() == "") {
        cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_end;
        createConnection(remote_end, gOpt.getSeqWindowSize(),mux);
      }
      
      ConnectionMap::iterator cit = gConnectionList.getConnection(mux);
      if (cit == gConnectionList.getEnd())
        continue;
      ConnectionParam & conn = cit->second;
      
          // check whether auth tag is ok or not
      if(!a->checkTag(conn.kd_, encrypted_packet)) {
        cLog.msg(Log::PRIO_NOTICE) << "wrong Authentication Tag!" << std::endl;
        continue;
      }        

          // Replay Protection
      if(conn.seq_window_.checkAndAdd(encrypted_packet.getSenderId(), encrypted_packet.getSeqNr())) {
        cLog.msg(Log::PRIO_NOTICE) << "Replay attack from " << conn.remote_end_ 
                                   << " seq:"<< encrypted_packet.getSeqNr() << " sid: "<< encrypted_packet.getSenderId();
        continue;
      }
      
          //Allow dynamic IP changes 
          //TODO: add command line option to turn this off
      if (remote_end != conn.remote_end_) {
        cLog.msg(Log::PRIO_NOTICE) << "connection "<< mux << " autodetected remote host ip changed " << remote_end;
        conn.remote_end_=remote_end;
#ifndef ANYTUN_NOSYNC
        SyncCommand sc (gConnectionList,mux);
        gSyncQueue.push(sc);
#endif
      }	
         // ignore zero length packets
      if(encrypted_packet.getPayloadLength() <= PlainPacket::getHeaderLength())
        continue;

          // decrypt packet
      c->decrypt(conn.kd_, encrypted_packet, plain_packet);
      
          // check payload_type
      if((param->dev.getType() == TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN4 && 
                                              plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN6) ||
         (param->dev.getType() == TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP))
        continue;
      
          // write it on the device
      param->dev.write(plain_packet.getPayload(), plain_packet.getLength());
    }
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERR) << "receiver thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERR) << "receiver thread died due to an uncaught exception: " << e.what();
  }
}

 
int main(int argc, char* argv[])
{
  bool daemonized=false;
  try 
  {
    cLog.msg(Log::PRIO_NOTICE) << "anytun started...";
///  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;

    try 
    {
      bool result = gOpt.parse(argc, argv);
      if(!result) {
        cLog.msg(Log::PRIO_NOTICE) << "printing help text and exitting";
        gOpt.printUsage();
        exit(0);
      }
    }
    catch(syntax_error& e)
    {
      std::cerr << e << std::endl;
      cLog.msg(Log::PRIO_NOTICE) << "exitting after syntax error";
      gOpt.printUsage();
      exit(-1);
    }

#ifndef NO_DAEMON
    PrivInfo privs(gOpt.getUsername(), gOpt.getGroupname());

    std::ofstream pidFile;
    if(gOpt.getPidFile() != "") {
      pidFile.open(gOpt.getPidFile().c_str());
      if(!pidFile.is_open()) {
        std::cout << "can't open pid file" << std::endl;
      }
    }
#endif
    
#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
// this must be called before any other libgcrypt call
    if(!initLibGCrypt())
      return -1;
#endif
#endif

    TunDevice dev(gOpt.getDevName(), gOpt.getDevType(), gOpt.getIfconfigParamLocal(), gOpt.getIfconfigParamRemoteNetmask());
    cLog.msg(Log::PRIO_NOTICE) << "dev opened - name '" << dev.getActualName() << "', node '" << dev.getActualNode() << "'";
    cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << dev.getTypeString() << "'";
#ifndef NO_EXEC
    if(gOpt.getPostUpScript() != "") {
      cLog.msg(Log::PRIO_NOTICE) << "executing post-up script '" << gOpt.getPostUpScript() << "'";
      execScript(gOpt.getPostUpScript(), dev.getActualName(), dev.getActualNode());
    }
#endif
    
    PacketSource* src;
    if(gOpt.getLocalAddr() == "")
      src = new UDPPacketSource(gOpt.getLocalPort());
    else
      src = new UDPPacketSource(gOpt.getLocalAddr(), gOpt.getLocalPort());

    HostList connect_to = gOpt.getRemoteSyncHosts();
    SyncQueue queue;
    
    if(gOpt.getRemoteAddr() != "")
    {
      boost::asio::io_service io_service;
      UDPPacketSource::proto::resolver resolver(io_service);
      UDPPacketSource::proto::resolver::query query(gOpt.getRemoteAddr(), gOpt.getRemotePort());
      UDPPacketSource::proto::endpoint endpoint = *resolver.resolve(query);
      createConnection(endpoint,gOpt.getSeqWindowSize(), gOpt.getMux());
    }    

#ifndef NO_ROUTING
    NetworkList routes = gOpt.getRoutes();
		NetworkList::const_iterator rit;
		for(rit = routes.begin(); rit != routes.end(); ++rit)
		{
			NetworkAddress addr( rit->net_addr );
			NetworkPrefix prefix( addr, static_cast<u_int8_t>(rit->prefix_length));
			gRoutingTable.addRoute( prefix, gOpt.getMux() );
		}
		if (connect_to.begin() == connect_to.end() && routes.begin() == routes.end() && gOpt.getDevType()=="tun")
		{
			std::cout << "No Routes and no syncronisation hosts have be specified"<< std::endl;
			std::cout << "anytun won't be able to send any data"<< std::endl;
			std::cout << "most likely you want to add --route 0.0.0.0/0 --route ::/0"<< std::endl;
			std::cout << "to your command line to allow both ipv4 and ipv6 traffic"<< std::endl;
			std::cout << "(this does not set operating system routes, use the post-up script"<< std::endl;
			std::cout << " to set them)"<< std::endl;
			return -1;
		}
#endif
#ifndef NO_DAEMON
    if(gOpt.getChrootDir() != "")
      do_chroot(gOpt.getChrootDir());

    privs.drop();

    if(gOpt.getDaemonize()) {
      daemonize();
      daemonized = true;
    }

    if(pidFile.is_open()) {
      pid_t pid = getpid();
      pidFile << pid;
      pidFile.close();
    }
#endif

#ifndef NO_SIGNALCONTROLLER
    SignalController sig;
    sig.init();
#endif

    OptionHost* connTo = new OptionHost();
    ThreadParam p(dev, *src, *connTo);

    boost::thread senderThread(boost::bind(sender,&p));
#ifndef NO_SIGNALCONTROLLER
    boost::thread receiverThread(boost::bind(receiver,&p)); 
#endif
#ifndef ANYTUN_NOSYNC
    boost::thread * syncListenerThread;
    if(gOpt.getLocalSyncPort() != "")
      syncListenerThread = new boost::thread(boost::bind(syncListener,&queue));
    
    std::list<boost::thread *> connectThreads;
    for(HostList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it) { 
      ThreadParam * point = new ThreadParam(dev, *src, *it);
      connectThreads.push_back(new boost::thread(boost::bind(syncConnector,point)));
    }
#endif

#ifndef NO_SIGNALCONTROLLER
    int ret = sig.run();  
#else
    receiver(&p);
    int ret = 0;
#endif
    // TODO cleanup threads here!
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
    if(src)
      delete src;
    if(connTo)
      delete connTo;
    */
    return ret; 
  }
  catch(std::runtime_error& e)
  {
    cLog.msg(Log::PRIO_ERR) << "uncaught runtime error, exiting: " << e.what();
#ifndef LOG_STDOUT
	if(!daemonized)
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
#endif
  }
  catch(std::exception& e)
  {
    cLog.msg(Log::PRIO_ERR) << "uncaught exception, exiting: " << e.what();
#ifndef LOG_STDOUT    
	if(!daemonized)
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
#endif  
  }
}
  
  
