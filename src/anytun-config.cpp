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
#include <poll.h>

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "keyDerivation.h"
#include "keyDerivationFactory.h"
#include "anyConfOptions.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"
#include "packetSource.h"

#include "syncQueue.h"
#include "syncCommand.h"



void createConnection(const PacketSourceEndpoint & remote_end, ConnectionList & cl, u_int16_t seqSize, SyncQueue & queue, mux_t mux)
{
  SeqWindow * seq = new SeqWindow(seqSize);
  seq_nr_t seq_nr_ = 0;
  KeyDerivation * kd = KeyDerivationFactory::create( gOpt.getKdPrf() );
  kd->init( gOpt.getKey(), gOpt.getSalt() );
//  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_end;
  ConnectionParam connparam ( (*kd), (*seq), seq_nr_, remote_end );
  cl.addConnection( connparam, mux );

  std::ostringstream sout;
  boost::archive::text_oarchive oa( sout );
  const SyncCommand scom( cl, mux );

  oa << scom;
  std::cout <<  std::setw(5) << std::setfill('0') << sout.str().size()<< ' ' << sout.str() << std::endl;

  RouteList routes = gOpt.getRoutes();
  RouteList::const_iterator rit;
  for(rit = routes.begin(); rit != routes.end(); ++rit)
  {
    NetworkAddress addr( rit->net_addr.c_str() );
    NetworkPrefix prefix( addr, rit->prefix_length );
    
    gRoutingTable.addRoute( prefix, mux );
    
    std::ostringstream sout2;
    boost::archive::text_oarchive oa2( sout2 );
    const SyncCommand scom2( prefix );
    
    oa2 << scom2;
    std::cout <<  std::setw(5) << std::setfill('0') << sout2.str().size()<< ' ' << sout2.str() << std::endl;
  }    
}

int main(int argc, char* argv[])
{
  int ret=0;
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }

	ConnectionList cl;
	SyncQueue queue;

	UDPPacketSource::proto::endpoint endpoint;
	if (gOpt.getRemoteAddr()!="" && gOpt.getRemotePort()!="")
	{
		boost::asio::io_service io_service;
		UDPPacketSource::proto::resolver resolver(io_service);
		UDPPacketSource::proto::resolver::query query(gOpt.getRemoteAddr(), gOpt.getRemotePort());
		endpoint = *resolver.resolve(query);
  }
	createConnection(endpoint,cl,gOpt.getSeqWindowSize(), queue, gOpt.getMux());

  return ret;
}

