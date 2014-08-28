/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include "boost/tuple/tuple.hpp"
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
#if !defined(_MSC_VER) && !defined(MINGW)
# include "daemonService.h"
#else
# ifdef WIN_SERVICE
#  include "win32/winService.h"
# else
#  include "nullDaemon.h"
# endif
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

#include "cryptinit.hpp"
#include "channel.hpp"
#include "sysExec.h"

bool disableRouting = false;

void createConnection(const PacketSourceEndpoint& remote_end, window_size_t seqSize, mux_t mux)
{
  SeqWindow* seq = new SeqWindow(seqSize);
  seq_nr_t seq_nr_=0;
  KeyDerivation* kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt(), gOpt.getPassphrase());
  kd->setRole(gOpt.getRole());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;

  ConnectionParam connparam((*kd), (*seq), seq_nr_, remote_end);
  gConnectionList.addConnection(connparam,mux);
#ifndef ANYTUN_NOSYNC
  SyncCommand sc(gConnectionList,mux);
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
  try {
    SyncServer server(gOpt.getLocalSyncAddr(), gOpt.getLocalSyncPort(), boost::bind(syncOnConnect, _1));
    gSyncQueue.setSyncServerPtr(&server);
    server.run();
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught exception: " << e.what();
  }
}
#endif

// Start 1 Thread per Tun device
void threadReadTunDeviceAndWriteToPlainInQueue(TunDevice* dev, Channel<PlainPacket*>* plain_in_queue, Channel<PlainPacket*>* plain_memory_pool )
{
  if(!dev || !plain_in_queue || ! plain_memory_pool) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadTunDeviceAndWriteToEncryptedQueue died because either dev or plain_in_queue or plain_memory_pool, pointer is null";
    return;
  }
  cLog.msg(Log::PRIO_DEBUG) << "started threadReadTunDeviceAndWriteToPlainInQueue";
  try {
    for(;;) {
//      cLog.msg(Log::PRIO_DEBUG) << "threadReadTunDeviceAndWriteToPlainInQueue loop";
      PlainPacket * plain_packet = NULL;
      plain_memory_pool->pop(&plain_packet);
      plain_packet->setLength(MAX_PACKET_LENGTH);
//      cLog.msg(Log::PRIO_DEBUG) << "threadReadTunDeviceAndWriteToPlainInQueue after pop";

      // read packet from device
      int len = dev->read(plain_packet->getPayload(), plain_packet->getPayloadLength());
      if(len < 0) {
        plain_memory_pool->push(plain_packet);
        continue;  // silently ignore device read errors, this is probably no good idea...
      }

      if(static_cast<uint32_t>(len) < PlainPacket::getHeaderLength()) {
        plain_memory_pool->push(plain_packet);
        continue;  // ignore short packets
      }
      plain_packet->setPayloadLength(len);
      // set payload type
      if(dev->getType() == TYPE_TUN) {
        plain_packet->setPayloadType(PAYLOAD_TYPE_TUN);
      } else if(dev->getType() == TYPE_TAP) {
        plain_packet->setPayloadType(PAYLOAD_TYPE_TAP);
      } else {
        plain_packet->setPayloadType(0);
      }
      plain_in_queue->push(plain_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadTunDeviceAndWriteToPlainInQueue died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadTunDeviceAndWriteToPlainInQueue died due to an uncaught exception: " << e.what();
  }
}

void threadReadPlainInQueueAndWriteEncryptedOutQueue(Channel<PlainPacket*>* plain_in_queue, Channel<PlainPacket*>* plain_memory_pool, Channel<EncryptedPacket*>* encrypted_out_queue, Channel<EncryptedPacket*>* encrypted_memory_pool)
{
  if(!plain_in_queue || !plain_memory_pool || !encrypted_out_queue || !encrypted_memory_pool) {
    cLog.msg(Log::PRIO_ERROR) << "sender thread died because either plain_in_queue or plain_memory_pool or encrypted_out_queue or encrypted_memory_pool pointer is null";
    return;
  }
  cLog.msg(Log::PRIO_DEBUG) << "started threadReadPlainInQueueAndWriteEncryptedOutQueue";

  try {
    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_OUTBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_OUTBOUND));


    uint16_t mux = gOpt.getMux();
    PacketSourceEndpoint emptyEndpoint;
    for(;;) {
      PlainPacket * plain_packet = NULL;
      plain_in_queue->pop(&plain_packet);
      EncryptedPacket * encrypted_packet = NULL;
      encrypted_memory_pool->pop(&encrypted_packet);
      encrypted_packet->withAuthTag(false);
      encrypted_packet->setLength(MAX_PACKET_LENGTH);

      if(gConnectionList.empty()) {
        plain_memory_pool->push(plain_packet);        
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }
      //std::cout << "got Packet for plain "<<plain_packet.getDstAddr().toString();
      ConnectionMap::iterator cit;
#ifndef NO_ROUTING
      if(!disableRouting)
        try {
          mux = gRoutingTable.getRoute(plain_packet->getDstAddr());
          //std::cout << " -> "<<mux << std::endl;
          cit = gConnectionList.getConnection(mux);
        } catch(std::exception&) { 
          plain_memory_pool->push(plain_packet);
          encrypted_memory_pool->push(encrypted_packet);
          continue; 
        }  // no route
      else {
        cit = gConnectionList.getBegin();
      }
#else
      cit = gConnectionList.getBegin();
#endif

      if(cit==gConnectionList.getEnd()) {
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;  //no connection
      }
      ConnectionParam& conn = cit->second;

      if(conn.remote_end_ == emptyEndpoint) {
        //cLog.msg(Log::PRIO_INFO) << "no remote address set";
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }

      // encrypt packet
      c->encrypt(conn.kd_, *plain_packet, *encrypted_packet, conn.seq_nr_, gOpt.getSenderId(), mux);

      encrypted_packet->setHeader(conn.seq_nr_, gOpt.getSenderId(), mux);
      conn.seq_nr_++;

      // add authentication tag
      a->generate(conn.kd_, *encrypted_packet);

      encrypted_packet->setEndpoint(conn.remote_end_);
      plain_memory_pool->push(plain_packet);
      encrypted_out_queue->push(encrypted_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadPlainInQueueAndWriteEncryptedOutQueue died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadPlainInQueueAndWriteEncryptedOutQueue died due to an uncaught exception: " << e.what();
  }
}

void threadWriteToSocket(Channel<EncryptedPacket*>* encrypted_out_queue, Channel<EncryptedPacket*>* encrypted_memory_pool, PacketSource* src)
{
  if(!encrypted_out_queue || !encrypted_memory_pool || !src) {
    cLog.msg(Log::PRIO_ERROR) << "sender thread died because either encrypted_out_queue or encrypted_memory_pool, or src pointer is null";
    return;
  }
  cLog.msg(Log::PRIO_DEBUG) << "started threadWriteToSocket";
  try {
    for(;;) {
      EncryptedPacket  * encrypted_packet = NULL;
      encrypted_out_queue->pop(&encrypted_packet);
      try {
        src->send(encrypted_packet->getBuf(), encrypted_packet->getLength(), encrypted_packet->getEndpoint());
      } catch(std::exception& /*e*/) {
        //TODO: do something here
        //cLog.msg(Log::PRIO_ERROR) << "could not send data: " << e.what();
      }
      encrypted_memory_pool->push(encrypted_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadWriteToSocket died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadWriteToSocket died due to an uncaught exception: " << e.what();
  }
}

void threadReadSocketAndWriteToEncryptedInQueue( PacketSource*src, Channel<EncryptedPacket*>* encrypted_in_queue, Channel<EncryptedPacket*>* encrypted_memory_pool)
{
  if(!src || ! encrypted_in_queue || ! encrypted_memory_pool) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died because either src or encrypted_in_queue encrypted_memory_pool pointer is null";
    return;
  }

  try {
    uint32_t auth_tag_length = gOpt.getAuthTagLength();

    for(;;) {
      EncryptedPacket * encrypted_packet = NULL;
      encrypted_memory_pool->pop(&encrypted_packet);
      encrypted_packet->setLength(MAX_PACKET_LENGTH);
      PacketSourceEndpoint remote_end;

      encrypted_packet->withAuthTag(false);
      encrypted_packet->setLength(MAX_PACKET_LENGTH);

      // read packet from socket
      int len;
      try {
        len = src->recv(encrypted_packet->getBuf(), encrypted_packet->getLength(), remote_end);
      } catch(std::exception& /*e*/) {
        //TODO: do something here
        //cLog.msg(Log::PRIO_ERROR) << "could not recive packet "<< e.what();
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }
      if(len < 0) {
        encrypted_memory_pool->push(encrypted_packet);
        continue;  // silently ignore socket recv errors, this is probably no good idea...
      }

      if(static_cast<uint32_t>(len) < (EncryptedPacket::getHeaderLength() + auth_tag_length)) {
        encrypted_memory_pool->push(encrypted_packet);
        continue;  // ignore short packets
      }
      encrypted_packet->setLength(len);
      encrypted_packet->setEndpoint(remote_end);
      encrypted_in_queue->push(encrypted_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadSocketAndWriteToEncryptedInQueue thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadSocketAndWriteToEncryptedInQueue thread died due to an uncaught exception: " << e.what();
  }

}

void threadReadEncryptedInQueueAndWritePlainOutQueue(Channel<EncryptedPacket*>* encrypted_in_queue, Channel<EncryptedPacket*>* encrypted_memory_pool, Channel<PlainPacket*>* plain_out_queue, Channel<PlainPacket*>* plain_memory_pool)
{
  if(!encrypted_in_queue || !encrypted_memory_pool || !plain_out_queue || !plain_memory_pool) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died because either encrypted_in_queue or encrypted_memory_pool or plain_out_queue or plain_memory_pool pointer is null";
    return;
  }
  try {
    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_INBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_INBOUND));
    for(;;) {
      PlainPacket * plain_packet = NULL;
      plain_memory_pool->pop(&plain_packet);
      plain_packet->setLength(MAX_PACKET_LENGTH);
      EncryptedPacket * encrypted_packet = NULL;
      encrypted_in_queue->pop(&encrypted_packet);
      PacketSourceEndpoint remote_end = encrypted_packet->getEndpoint();
      mux_t mux = encrypted_packet->getMux();
      // autodetect peer
      if(gConnectionList.empty() && gOpt.getRemoteAddr() == "") {
        cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_end;
        createConnection(remote_end, gOpt.getSeqWindowSize(),mux);
      }

      ConnectionMap::iterator cit = gConnectionList.getConnection(mux);
      if(cit == gConnectionList.getEnd()) {
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }
      ConnectionParam& conn = cit->second;

      // check whether auth tag is ok or not
      if(!a->checkTag(conn.kd_, *encrypted_packet)) {
        cLog.msg(Log::PRIO_NOTICE) << "wrong Authentication Tag!";
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }

      // Replay Protection
      if(conn.seq_window_.checkAndAdd(encrypted_packet->getSenderId(), encrypted_packet->getSeqNr())) {
        cLog.msg(Log::PRIO_NOTICE) << "Replay attack from " << conn.remote_end_
                                   << " seq:"<< encrypted_packet->getSeqNr() << " sid: "<< encrypted_packet->getSenderId();
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }

      //Allow dynamic IP changes
      //TODO: add command line option to turn this off
      if(remote_end != conn.remote_end_) {
        cLog.msg(Log::PRIO_NOTICE) << "connection "<< mux << " autodetected remote host ip changed " << remote_end;
        conn.remote_end_=remote_end;
#ifndef ANYTUN_NOSYNC
        SyncCommand sc(gConnectionList,mux);
        gSyncQueue.push(sc);
#endif
      }
      // ignore zero length packets
      if(encrypted_packet->getPayloadLength() <= PlainPacket::getHeaderLength()) {
        plain_memory_pool->push(plain_packet);
        encrypted_memory_pool->push(encrypted_packet);
        continue;
      }

      // decrypt packet
      c->decrypt(conn.kd_, *encrypted_packet, *plain_packet);

      plain_out_queue->push(plain_packet);
      encrypted_memory_pool->push(encrypted_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadEncryptedInQueueAndWritePlainOutQueue thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadReadEncryptedInQueueAndWritePlainOutQueue thread died due to an uncaught exception: " << e.what();
  }

}

void threadWriteToTunDevice( Channel<PlainPacket*>* plain_out_queue, Channel<PlainPacket*>* plain_memory_pool, TunDevice* dev)
{
  try {
    for(;;) {
      PlainPacket * plain_packet = NULL;
      plain_out_queue->pop(&plain_packet);
      if((dev->getType() == TYPE_TUN && plain_packet->getPayloadType() != PAYLOAD_TYPE_TUN4 &&
          plain_packet->getPayloadType() != PAYLOAD_TYPE_TUN6) ||
          (dev->getType() == TYPE_TAP && plain_packet->getPayloadType() != PAYLOAD_TYPE_TAP)) {
        plain_memory_pool->push(plain_packet);
        continue;
      }

      // write it on the device
      dev->write(plain_packet->getPayload(), plain_packet->getLength());
      plain_memory_pool->push(plain_packet);
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadWriteToTunDevice thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "threadWriteToTunDevice thread died due to an uncaught exception: " << e.what();
  }

}

void receiver(TunDevice* dev, PacketSource* src)
{
  if(!dev || !src) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died because either dev or src pointer is null";
    return;
  }

  try {
    std::auto_ptr<Cipher> c(CipherFactory::create(gOpt.getCipher(), KD_INBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create(gOpt.getAuthAlgo(), KD_INBOUND));

    uint32_t auth_tag_length = gOpt.getAuthTagLength();
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, auth_tag_length);
    PlainPacket plain_packet(MAX_PACKET_LENGTH);

    for(;;) {
      PacketSourceEndpoint remote_end;

      plain_packet.setLength(MAX_PACKET_LENGTH);
      encrypted_packet.withAuthTag(false);
      encrypted_packet.setLength(MAX_PACKET_LENGTH);

      // read packet from socket
      int len;
      try {
        len = src->recv(encrypted_packet.getBuf(), encrypted_packet.getLength(), remote_end);
      } catch(std::exception& /*e*/) {
        //TODO: do something here
        //cLog.msg(Log::PRIO_ERROR) << "could not recive packet "<< e.what();
        continue;
      }
      if(len < 0) {
        continue;  // silently ignore socket recv errors, this is probably no good idea...
      }

      if(static_cast<uint32_t>(len) < (EncryptedPacket::getHeaderLength() + auth_tag_length)) {
        continue;  // ignore short packets
      }
      encrypted_packet.setLength(len);

      mux_t mux = encrypted_packet.getMux();
      // autodetect peer
      if(gConnectionList.empty() && gOpt.getRemoteAddr() == "") {
        cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_end;
        createConnection(remote_end, gOpt.getSeqWindowSize(),mux);
      }

      ConnectionMap::iterator cit = gConnectionList.getConnection(mux);
      if(cit == gConnectionList.getEnd()) {
        continue;
      }
      ConnectionParam& conn = cit->second;

      // check whether auth tag is ok or not
      if(!a->checkTag(conn.kd_, encrypted_packet)) {
        cLog.msg(Log::PRIO_NOTICE) << "wrong Authentication Tag!";
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
      if(remote_end != conn.remote_end_) {
        cLog.msg(Log::PRIO_NOTICE) << "connection "<< mux << " autodetected remote host ip changed " << remote_end;
        conn.remote_end_=remote_end;
#ifndef ANYTUN_NOSYNC
        SyncCommand sc(gConnectionList,mux);
        gSyncQueue.push(sc);
#endif
      }
      // ignore zero length packets
      if(encrypted_packet.getPayloadLength() <= PlainPacket::getHeaderLength()) {
        continue;
      }

      // decrypt packet
      c->decrypt(conn.kd_, encrypted_packet, plain_packet);

      // check payload_type
      if((dev->getType() == TYPE_TUN && plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN4 &&
          plain_packet.getPayloadType() != PAYLOAD_TYPE_TUN6) ||
          (dev->getType() == TYPE_TAP && plain_packet.getPayloadType() != PAYLOAD_TYPE_TAP)) {
        continue;
      }

      // write it on the device
      dev->write(plain_packet.getPayload(), plain_packet.getLength());
    }
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "receiver thread died due to an uncaught exception: " << e.what();
  }
}

void startSendRecvThreads(TunDevice* dev, PacketSource* src)
{
  unsigned int nthreads = boost::thread::hardware_concurrency();
  if (!nthreads)
    nthreads = 4;

  src->waitUntilReady();

  uint16_t plain_in_queue_length = 2 * nthreads + 4;
  Channel<PlainPacket*>* plain_in_queue = new Channel<PlainPacket*>(plain_in_queue_length);

  uint16_t plain_out_queue_length = 2 * nthreads + 4;
  Channel<PlainPacket*>* plain_out_queue = new Channel<PlainPacket*>(plain_out_queue_length);

  uint16_t plain_memory_pool_length = plain_in_queue_length + plain_out_queue_length + 1; 
  Channel<PlainPacket*>*  plain_memory_pool = new Channel<PlainPacket*>(plain_memory_pool_length);

  for(uint16_t cnt=0; cnt < plain_memory_pool_length; cnt++) {
    plain_memory_pool->push(new PlainPacket(MAX_PACKET_LENGTH));
  }

  uint16_t encrypted_out_queue_length = plain_in_queue_length;
  Channel<EncryptedPacket*>* encrypted_out_queue = new Channel<EncryptedPacket*>(encrypted_out_queue_length);

  uint16_t encrypted_in_queue_length = plain_in_queue_length;
  Channel<EncryptedPacket*>* encrypted_in_queue = new Channel<EncryptedPacket*>(encrypted_in_queue_length);

  uint16_t encrypted_memory_pool_length = encrypted_out_queue_length + encrypted_in_queue_length + 1; 
  Channel<EncryptedPacket*>*  encrypted_memory_pool = new Channel<EncryptedPacket*>(encrypted_memory_pool_length);

  uint32_t auth_tag_length = gOpt.getAuthTagLength();
  for(uint16_t cnt=0; cnt < encrypted_memory_pool_length; cnt++) {
    encrypted_memory_pool->push(new EncryptedPacket(MAX_PACKET_LENGTH, auth_tag_length));
  }

  boost::thread(boost::bind(threadReadTunDeviceAndWriteToPlainInQueue, dev, plain_in_queue, plain_memory_pool));
//  for(uint16_t cnt=0; cnt < nthreads; cnt++) {
    boost::thread(boost::bind(threadReadPlainInQueueAndWriteEncryptedOutQueue, plain_in_queue, plain_memory_pool, encrypted_out_queue, encrypted_memory_pool));
//  }
  boost::thread(boost::bind(threadWriteToSocket, encrypted_out_queue, encrypted_memory_pool, src));


  boost::thread(boost::bind(threadReadSocketAndWriteToEncryptedInQueue, src, encrypted_in_queue, encrypted_memory_pool));
//  for(uint16_t cnt=0; cnt < nthreads; cnt++) {
    boost::thread(boost::bind(threadReadEncryptedInQueueAndWritePlainOutQueue, encrypted_in_queue, encrypted_memory_pool, plain_out_queue, plain_memory_pool));
//  }
  boost::thread(boost::bind(threadWriteToTunDevice, plain_out_queue, plain_memory_pool, dev));
}


#ifdef WIN_SERVICE
int main(int argc, char* argv[])
{
  try {
    if(argc > 1) {
      if(std::string(argv[1]) == "install") {
        WinService::install();
        return 0;
      } else if(std::string(argv[1]) == "uninstall") {
        WinService::uninstall();
        return 0;
      }
    }
    WinService::start();
    return 0;
  } catch(std::runtime_error& e) {
    std::cout << "caught runtime error, exiting: " << e.what() << std::endl;
  } catch(std::exception& e) {
    std::cout << "caught exception, exiting: " << e.what() << std::endl;
  }
}

int real_main(int argc, char* argv[], WinService& service)
{
#else
int main(int argc, char* argv[])
{
  DaemonService service;
#endif
  try {
    try {
      if(!gOpt.parse(argc, argv)) {
        exit(0);
      }

      StringList targets = gOpt.getLogTargets();
      for(StringList::const_iterator it = targets.begin(); it != targets.end(); ++it) {
        cLog.addTarget(*it);
      }
    } catch(syntax_error& e) {
      std::cerr << e << std::endl;
      gOpt.printUsage();
      exit(-1);
    }

    cLog.msg(Log::PRIO_NOTICE) << "anytun started...";
    gOpt.parse_post(); // print warnings

    // daemonizing has to done before any thread gets started
    service.initPrivs(gOpt.getUsername(), gOpt.getGroupname());
    if(gOpt.getDaemonize()) {
      service.daemonize();
    }

    OptionNetwork net = gOpt.getIfconfigParam();
    TunDevice dev(gOpt.getDevName(), gOpt.getDevType(), net.net_addr, net.prefix_length);
    cLog.msg(Log::PRIO_NOTICE) << "dev opened - name '" << dev.getActualName() << "', node '" << dev.getActualNode() << "'";
    cLog.msg(Log::PRIO_NOTICE) << "dev type is '" << dev.getTypeString() << "'";

    SysExec* postup_script = NULL;
    if(gOpt.getPostUpScript() != "") {
      cLog.msg(Log::PRIO_NOTICE) << "executing post-up script '" << gOpt.getPostUpScript() << "'";
      StringVector args = boost::assign::list_of(dev.getActualName())(dev.getActualNode());
      postup_script = new SysExec(gOpt.getPostUpScript(), args);
    }

    if(gOpt.getChrootDir() != "") {
      try {
        service.chroot(gOpt.getChrootDir());
      } catch(const std::runtime_error& e) {
        cLog.msg(Log::PRIO_WARNING) << "ignoring chroot error: " << e.what();
      }
    }
    service.dropPrivs();

    // this has to be called before the first thread is started
    gSignalController.init(service);
    gResolver.init();
    boost::thread(boost::bind(&TunDevice::waitUntilReady,&dev));
    if(postup_script) {
      boost::thread(boost::bind(&SysExec::waitAndDestroy,postup_script));
    }

    initCrypto();

    PacketSource* src = new UDPPacketSource(gOpt.getLocalAddr(), gOpt.getLocalPort());

    if(gOpt.getRemoteAddr() != "") {
      gResolver.resolveUdp(gOpt.getRemoteAddr(), gOpt.getRemotePort(), boost::bind(createConnectionResolver, _1, gOpt.getSeqWindowSize(), gOpt.getMux()), boost::bind(createConnectionError, _1), gOpt.getResolvAddrType());
    }

    HostList connect_to = gOpt.getRemoteSyncHosts();
#ifndef NO_ROUTING
    NetworkList routes = gOpt.getRoutes();
    NetworkList::const_iterator rit;
    for(rit = routes.begin(); rit != routes.end(); ++rit) {
      NetworkAddress addr(rit->net_addr);
      NetworkPrefix prefix(addr, static_cast<uint8_t>(rit->prefix_length));
      gRoutingTable.addRoute(prefix, gOpt.getMux());
    }
    if(connect_to.begin() == connect_to.end() || gOpt.getDevType()!="tun") {
      cLog.msg(Log::PRIO_NOTICE) << "No sync/control host defined or not a tun device. Disabling multi connection support (routing)";
      disableRouting=true;
    }
#endif

#ifndef ANYTUN_NOSYNC
    boost::thread* syncListenerThread = NULL;
    if(gOpt.getLocalSyncPort() != "") {
      syncListenerThread = new boost::thread(boost::bind(syncListener));
      if(syncListenerThread) syncListenerThread->detach();
    }

    boost::thread_group connectThreads;
    for(HostList::const_iterator it = connect_to.begin() ; it != connect_to.end(); ++it) {
      connectThreads.create_thread(boost::bind(syncConnector, *it));
    }
#endif

    // wait for packet source to finish in a seperate thread in order
    // to be still able to process signals while waiting
    boost::thread(boost::bind(startSendRecvThreads, &dev, src));

    int ret = gSignalController.run();

    // TODO: stop all threads and cleanup
    //
    //     if(src)
    //       delete src;
    //     if(connTo)
    //       delete connTo;
    return ret;
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "uncaught runtime error, exiting: " << e.what();
    if(!service.isDaemonized()) {
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
    }
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "uncaught exception, exiting: " << e.what();
    if(!service.isDaemonized()) {
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
    }
  }
  return -1;
}


