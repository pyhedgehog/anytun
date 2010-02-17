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

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "keyDerivation.h"
#include "seqWindow.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"
#include "syncCommand.h"

#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


void output()
{
  ConnectionList& cl(gConnectionList);
  if(!cl.empty()) {
    ConnectionMap::iterator it = cl.getBeginUnlocked();
    mux_t mux = it->first;
    ConnectionParam& conn(it->second);
    std::cout << "Client " << mux << ": " ;
    if(conn.remote_end_==PacketSourceEndpoint()) {
      std::cout<< "not registered";
    } else {
      std::cout<< conn.remote_end_;
    }
    std::cout << std::endl;
    //std::cout << "Connection: Keyderivation-Type: " << conn.kd_.printType() << std::endl;
    cl.clear();
  } else {
    network_address_type_t types[] = {ipv4,ipv6,ethernet};
    for(int types_idx=0; types_idx<3; types_idx++) {
      network_address_type_t type = types[types_idx];
      if(!gRoutingTable.empty(type)) {
        RoutingMap::iterator it = gRoutingTable.getBeginUnlocked(type);
        NetworkPrefix pref(it->first);
        std::cout << "Route: " << pref.toString() << "/" << (int)pref.getNetworkPrefixLength() << " -> ";
        mux_t mux = it->second;
        std::cout << mux << std::endl;
        gRoutingTable.clear(type);
      }
    }
  }
}

void readExactly(size_t toread, std::iostream& result)
{
  size_t hasread = 0;
  while(toread > hasread && std::cin.good()) {
    char a[1];
    std::cin.read(a,1);
    result.write(a,1);
    hasread++;
  }
}

void readAndProcessOne()
{
  size_t message_lenght ;
  std::stringstream message_lenght_stream;
  readExactly(5,message_lenght_stream);
  message_lenght_stream >> message_lenght;
  std::stringstream void_stream;
  readExactly(1,void_stream); //skip space
  if(!message_lenght) {
    return;
  }
  std::stringstream sync_command_stream;
  readExactly(message_lenght, sync_command_stream);
  //std::cout << message_lenght << std::endl;
  //std::cout << sync_command_stream.str()<< std::endl;
  boost::archive::text_iarchive ia(sync_command_stream);
  SyncCommand scom(gConnectionList);
  ia >> scom;
}

int main(int argc, char* argv[])
{
  int ret = 0;

  while(std::cin.good()) {
    try {
      readAndProcessOne();
    } catch(std::exception& e) {
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
    }
    output();
  }
  return ret;
}

