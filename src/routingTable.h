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

#ifndef ANYTUN_routingTable_h_INCLUDED
#define ANYTUN_routingTable_h_INCLUDED

#include <map>
#include <deque>

#include "threadUtils.hpp"
#include "datatypes.h"
#include "networkAddress.h"
#include "networkPrefix.h"
#include "routingTreeNode.h"
#include "boost/array.hpp"
typedef std::map<NetworkPrefix,uint16_t> RoutingMap;

class RoutingTable
{
public:
  static RoutingTable& instance();
  RoutingTable();
  ~RoutingTable();
  void addRoute(const NetworkPrefix& ,uint16_t);
  void updateRouteTreeUnlocked(const NetworkPrefix& pref);
  void delRoute(const NetworkPrefix&);
  uint16_t getRoute(const NetworkAddress&);
  bool empty(network_address_type_t type);
  void clear(network_address_type_t type);
  Mutex& getMutex();
  uint16_t* getOrNewRoutingTEUnlocked(const NetworkPrefix& addr);
  uint16_t getCountUnlocked(network_address_type_t type);
  RoutingMap::iterator getBeginUnlocked(network_address_type_t type);
  RoutingMap::iterator getEndUnlocked(network_address_type_t type);

private:
  static Mutex instMutex;
  static RoutingTable* inst;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(RoutingTable::inst != 0) {
        delete RoutingTable::inst;
      }
    }
  };
  RoutingTable(const RoutingTable& s);
  void operator=(const RoutingTable& s);
  boost::array<RoutingMap,3> routes_;
  boost::array<RoutingTreeNode,3> root_;
  Mutex mutex_;
};

extern RoutingTable& gRoutingTable;

#endif
