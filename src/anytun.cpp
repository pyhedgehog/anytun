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
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/assign.hpp>
#include <iostream>
#include <fstream>

#include "datatypes.h"

#include "log.h"
#include "resolver.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cipher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "cipherFactory.h"
#include "authAlgoFactory.h"
#include "keyDerivationFactory.h"
#include "signalController.h"
#ifdef WIN_SERVICE
#include "win32/winService.h"
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

#define MAX_PACKET_LENGTH 1600

#include "cryptinit.hpp"
#include "daemon.hpp"
#include "sysExec.h"

bool disableRouting = false;

void createConnection(const PacketSourceEndpoint& remote_end, window_size_t seqSize, mux_t mux)
{
	SeqWindow* seq = new SeqWindow(seqSize);
	seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt(), gOpt.getPassphrase());
  kd->setRole(gOpt.getRole());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;

	ConnectionParam connparam ((*kd), (*seq), seq_nr_, remote_end);
 	gConnectionList.addConnection(connparam,mux);
#ifndef ANYTUN_NOSYNC
  SyncCommand sc (gConnectionList,mux);
	gSyncQueue.push(sc);
#endif
}

void createConnectionResolver(PacketSourceResolverIt& it, window_size_t seqSize, mux_t mux)
{
  createConnection(*it, seqSize, mux);
}

void createConnectionError(const std::exception& e)
{
  gSignalController.inject(SIGERROR, e.what());
}

#ifndef ANYTUN_NOSYNC
void syncConnector(const OptionHost& connto)
{
  SyncClient sc(connto.addr, connto.port);
  sc.run();
}

void syncListener()
{
  try
  {
    SyncServer server(gOpt.getLocalSyncAddr(), gOpt.getLocalSyncPort(), boost::bind(syncOnConnect, _1));
    gSyncQueue.setSyncServerPtr(&server);
    server.run();
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught exception: " << e.what();
  }
}
#endif

void sender(TunDevice* dev, PacketSource* src)
{
  if(!dev || !src) {
    cLog.msg(Log::PRIO_ERROR) << "sender thread died because either dev or src pointer is null";    
    return;
  }

  try 
  {
    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_OUTBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_OUTBOUND) );
    
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, gOpt.getAuthTagLength());
    
    u_int16_t mux = gOpt.getMux();
    PacketSourceEndpoint emptyEndpoint;
    while(1) {
      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from device
      int len = dev->read(plain_packet.getPayload(), plain_packet.getPayloadLength());
      if(len < 0)
        continue; // silently ignore device read errors, this is probably no good idea...

      if(static_cast<u_int32_t>(len) < PlainPacket::getHeaderLength())
        continue; // ignore short packets
      plain_packet.setPayloadLength(len);
          // set payload type
      if(dev->getType() == TYPE_TUN)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
      else if(dev->getType() == TYPE_TAP)
        plain_packet.setPayloadType(PAYLOAD_TYPE_TAP);
      else 
        plain_packet.setPayloadType(0);
      
      if(gConnectionList.empty())
        continue;
          //std::cout << "got Packet for plain "<<plain_packet.getDstAddr().toString();
			ConnectionMap::iterator cit;
#ifndef NO_ROUTING
			if (!disableRouting)
				try {
					mux = gRoutingTable.getRoute(plain_packet.getDstAddr());
							//std::cout << " -> "<<mux << std::endl;
					cit = gConnectionList.getConnection(mux);
				} catch (std::exception&) { continue; } // no route
			else
				cit = gConnectionList.getBegin();
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
        src->send(encrypted_packet.getBuf(), encrypted_packet.getLength(), conn.remote_end_);
      } catch (std::exception& /*e*/) {
				//TODO: do something here
		  	//cLog.msg(Log::PRIO_ERROR) << "could not send data: " << e.what();
	  	} 
    }
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "sender thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "sender thread died due to an uncaught exception: " << e.what();
  }
}

void receiver(TunDevice* dev, PacketSource* src)
{
  if(!dev || !src) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died because either dev or src pointer is null";    
    return;
  }

  try 
  {
    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_INBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_INBOUND));
    
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, gOpt.getAuthTagLength());
    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    
    while(1) {
      PacketSourceEndpoint remote_end;

      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);
      
          // read packet from socket
      int len;
      try {
        len = src->recv(encrypted_packet.getBuf(), encrypted_packet.getLength(), remote_end);
      } catch (std::exception& /*e*/) { 
				//TODO: do something here
		  	//cLog.msg(Log::PRIO_ERROR) << "could not recive packet "<< e.what();
		  	continue; 
	  	}
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
      if((dev->getType() == TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN4 && 
                                              plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN6) ||
         (dev->getType() == TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP))
        continue;
      
          // write it on the device
      dev->write(plain_packet.getPayload(), plain_packet.getLength());
    }
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died due to an uncaught exception: " << e.what();
  }
}

void startSendRecvThreads(TunDevice* dev, PacketSource* src)
{
  src->waitUntilReady();
  
  boost::thread(boost::bind(sender, dev, src));
  boost::thread(boost::bind(receiver, dev, src)); 
}


#ifdef WIN_SERVICE
int main(int argc, char* argv[])
{
  try {
    if(argc > 1) {
      if(std::string(argv[1]) == "install") {
        WinService::install();  
        return 0;
      }
      else if(std::string(argv[1]) == "uninstall") {
        WinService::uninstall();  
        return 0;
      }
    }
    WinService::start();
    return 0;
  }
  catch(std::runtime_error& e)
  {
    std::cout << "caught runtime error, exiting: " << e.what() << std::endl;
  }
  catch(std::exception& e)
  {
    std::cout << "caught exception, exiting: " << e.what() << std::endl;
  }
}

int real_main(int argc, char* argv[])
#else
int main(int argc, char* argv[])
#endif
{
#ifdef WIN_SERVICE
  bool daemonized=true;
#else
  bool daemonized=false;
#endif  
  try 
  {
    try 
    {
      bool result = gOpt.parse(argc, argv);
      if(!result) {
        gOpt.printUsage();
        exit(0);
      }
      StringList targets = gOpt.getLogTargets();
      for(StringList::const_iterator it = targets.begin();it != targets.end(); ++it)
        cLog.addTarget(*it);
    }
    catch(syntax_error& e)
    {
      std::cerr << e << std::endl;
      gOpt.printUsage();
      exit(-1);
    }

    cLog.msg(Log::PRIO_NOTICE) << "anytun started...";
    gOpt.parse_post(); // print warnings

        // daemonizing has to done before any thread gets started
#ifndef NO_DAEMON
#ifndef NO_PRIVDROP
  	PrivInfo privs(gOpt.getUsername(), gOpt.getGroupname());
#endif
    if(gOpt.getDaemonize()) {
      daemonize();
      daemonized = true;
    }
#endif


    OptionNetwork net = gOpt.getIfconfigParam();
    TunDevice dev(gOpt.getDevName(), gOpt.getDevType(), net.net_addr, net.prefix_length);
    cLog.msg(Log::PRIO_NOTICE) << "dev opened - name '" << dev.getActualName() << "', node '" << dev.getActualNode() << "'";
    cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << dev.getTypeString() << "'";
#ifndef NO_EXEC
    SysExec * postup_script = NULL;
    if(gOpt.getPostUpScript() != "") {
      cLog.msg(Log::PRIO_NOTICE) << "executing post-up script '" << gOpt.getPostUpScript() << "'";
      StringVector args = boost::assign::list_of(dev.getActualName())(dev.getActualNode());
      postup_script = new SysExec(gOpt.getPostUpScript(), args);
    }
#endif
#ifndef NO_DAEMON
    if(gOpt.getChrootDir() != "") {
      try {
        do_chroot(gOpt.getChrootDir());
      }
      catch(const std::runtime_error& e) {
        cLog.msg(Log::PRIO_WARNING) << "ignoring chroot error: " << e.what();
      }
    }
#ifndef NO_PRIVDROP
    privs.drop();
#endif
#endif
#if !( defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
    // this has to be called before the first thread is started
    gSignalController.init();
#endif
    gResolver.init();
#ifndef NO_EXEC
    boost::thread(boost::bind(&TunDevice::waitForPostUpScript,&dev));
    if (postup_script)
      boost::thread(boost::bind(&SysExec::waitForScript,postup_script));
#endif   
    initCrypto();   
 
    PacketSource* src = new UDPPacketSource(gOpt.getLocalAddr(), gOpt.getLocalPort());

    if(gOpt.getRemoteAddr() != "")
      gResolver.resolveUdp(gOpt.getRemoteAddr(), gOpt.getRemotePort(), boost::bind(createConnectionResolver, _1, gOpt.getSeqWindowSize(), gOpt.getMux()), boost::bind(createConnectionError, _1), gOpt.getResolvAddrType());

    HostList connect_to = gOpt.getRemoteSyncHosts();
#ifndef NO_ROUTING
    NetworkList routes = gOpt.getRoutes();
		NetworkList::const_iterator rit;
		for(rit = routes.begin(); rit != routes.end(); ++rit) {
			NetworkAddress addr( rit->net_addr );
			NetworkPrefix prefix( addr, static_cast<u_int8_t>(rit->prefix_length));
			gRoutingTable.addRoute( prefix, gOpt.getMux() );
		}
		if (connect_to.begin() == connect_to.end() || gOpt.getDevType()!="tun") {
    	cLog.msg(Log::PRIO_NOTICE) << "No sync/control host defined or not a tun device. Disabling multi connection support (routing)";
			disableRouting=true;
		}
#endif

#ifndef ANYTUN_NOSYNC
    boost::thread* syncListenerThread = NULL;
    if(gOpt.getLocalSyncPort() != "")
      syncListenerThread = new boost::thread(boost::bind(syncListener));
    
    boost::thread_group connectThreads;
    for(HostList::const_iterator it = connect_to.begin() ;it != connect_to.end(); ++it)
      connectThreads.create_thread(boost::bind(syncConnector, *it));
#endif

    // wait for packet source to finish in a seperate thread in order
    // to be still able to process signals while waiting
    boost::thread(boost::bind(startSendRecvThreads, &dev, src));

#if defined(WIN_SERVICE)
    int ret = 0;
    gWinService.waitForStop();
#else
    int ret = gSignalController.run();  
#endif

// TODO: stop all threads and cleanup
// 
//     if(src)
//       delete src;
//     if(connTo)
//       delete connTo;

#if defined(WIN_SERVICE)
    gWinService.stop();
#endif
    return ret; 
  }
  catch(std::runtime_error& e)
  {
    cLog.msg(Log::PRIO_ERROR) << "uncaught runtime error, exiting: " << e.what();
    if(!daemonized)
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
  }
  catch(std::exception& e)
  {
    cLog.msg(Log::PRIO_ERROR) << "uncaught exception, exiting: " << e.what();
    if(!daemonized)
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
  }
#if defined(WIN_SERVICE)
  gWinService.stop();
#endif
  return -1;
}
  
  
