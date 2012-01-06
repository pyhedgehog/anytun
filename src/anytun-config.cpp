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

#include <iostream>

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "keyDerivation.h"
#include "keyDerivationFactory.h"
#include "options.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"
#include "packetSource.h"
#include "resolver.h"

#include "syncQueue.h"
#include "syncCommand.h"



void createConnection(const PacketSourceEndpoint& remote_end, ConnectionList& cl, uint16_t seqSize, SyncQueue& queue, mux_t mux, Semaphore& sem)
{
  SeqWindow* seq = new SeqWindow(seqSize);
  seq_nr_t seq_nr_ = 0;
  KeyDerivation* kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt(), gOpt.getPassphrase());
  kd->setRole(gOpt.getRole());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;
  ConnectionParam connparam((*kd), (*seq), seq_nr_, remote_end);
  cl.addConnection(connparam, mux);

  std::ostringstream sout;
  boost::archive::text_oarchive oa(sout);
  const SyncCommand scom(cl, mux);

  oa << scom;
  std::cout <<  std::setw(5) << std::setfill('0') << sout.str().size()<< ' ' << sout.str() << std::endl;

  NetworkList routes = gOpt.getRoutes();
  NetworkList::const_iterator rit;
  for(rit = routes.begin(); rit != routes.end(); ++rit) {
    NetworkAddress addr(rit->net_addr.c_str());
    NetworkPrefix prefix(addr, rit->prefix_length);

    gRoutingTable.addRoute(prefix, mux);

    std::ostringstream sout2;
    boost::archive::text_oarchive oa2(sout2);
    const SyncCommand scom2(prefix);

    oa2 << scom2;
    std::cout <<  std::setw(5) << std::setfill('0') << sout2.str().size()<< ' ' << sout2.str() << std::endl;
  }
  sem.up();
}

void createConnectionResolver(PacketSourceResolverIt& it, ConnectionList& cl, uint16_t seqSize, SyncQueue& queue, mux_t mux, Semaphore& sem)
{
  createConnection(*it, cl, seqSize, queue, mux, sem);
}

void createConnectionError(const std::exception& e, Semaphore& sem, int& ret)
{
  cLog.msg(Log::PRIO_ERROR) << "uncaught runtime error: " << e.what();
  ret = -1;
  sem.up();
}

int main(int argc, char* argv[])
{
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

  gOpt.parse_post(); // print warnings

  gResolver.init();

  ConnectionList cl;
  SyncQueue queue;

  Semaphore sem;
  int ret = 0;
  UDPPacketSource::proto::endpoint endpoint;
  // allow emtpy endpoint!!!
  gResolver.resolveUdp(gOpt.getRemoteAddr(), gOpt.getRemotePort(),
                       boost::bind(createConnectionResolver, _1, boost::ref(cl), gOpt.getSeqWindowSize(), boost::ref(queue), gOpt.getMux(), boost::ref(sem)),
                       boost::bind(createConnectionError, _1, boost::ref(sem), boost::ref(ret)),
                       gOpt.getResolvAddrType());
  sem.down();
  return ret;
}

