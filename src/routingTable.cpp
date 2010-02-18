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
#include "networkPrefix.h"
#include "threadUtils.hpp"
#include "datatypes.h"
#include "anytunError.h"

#include "routingTable.h"
#include "routingTree.hpp"

RoutingTable* RoutingTable::inst = NULL;
Mutex RoutingTable::instMutex;
RoutingTable& gRoutingTable = RoutingTable::instance();


RoutingTable& RoutingTable::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst) {
    inst = new RoutingTable();
  }

  return *inst;
}

RoutingTable::RoutingTable()
{
}

RoutingTable::~RoutingTable()
{
}

void RoutingTable::updateRouteTreeUnlocked(const NetworkPrefix& pref)
{
  //Lock lock(mutex_); //deadlock

  uint8_t length=pref.getNetworkPrefixLength();
  network_address_type_t type=pref.getNetworkAddressType();
  uint16_t mux = routes_[pref.getNetworkAddressType()].find(pref)->second;
  RoutingTreeNode* node = &(root_[type]);
  if(type==ipv4) {
    ipv4_bytes_type bytes(pref.to_bytes_v4());
    if(length>32) {
      length=32;
    }
    RoutingTree::walk(bytes, node, length, mux);
  } else if(type==ipv6) {
    ipv6_bytes_type bytes(pref.to_bytes_v6());
    if(length>128) {
      length=128;
    }
    RoutingTree::walk(bytes, node, length, mux);
  } else if(type==ethernet) {
    ethernet_bytes_type bytes(pref.to_bytes_ethernet());
    if(length>48) {
      length=48;
    }
    RoutingTree::walk(bytes, node, length, mux);
  } else {
    AnytunError::throwErr() << "illegal protocol type";
  }
  //root_[type].print(0);
}

void RoutingTable::addRoute(const NetworkPrefix& pref, uint16_t mux)
{
  Lock lock(mutex_);

  network_address_type_t type=pref.getNetworkAddressType();

  if(type==ipv4 || type==ipv6) {
    std::pair<RoutingMap::iterator, bool> ret = routes_[type].insert(RoutingMap::value_type(pref,mux));
    if(!ret.second) {
      routes_[pref.getNetworkAddressType()].erase(ret.first);
      routes_[pref.getNetworkAddressType()].insert(RoutingMap::value_type(pref,mux));
    }
    root_[pref.getNetworkAddressType()]=RoutingTreeNode();
    RoutingMap::iterator it = routes_[type].begin();
    for(; it!=routes_[pref.getNetworkAddressType()].end(); ++it) {
      updateRouteTreeUnlocked(it->first);
    }
  } else if(type==ethernet) {
    return; // TODO: add support for ethernet
  } else {
    AnytunError::throwErr() << "illegal protocol type";
  }
}


void RoutingTable::delRoute(const NetworkPrefix& pref)
{
  Lock lock(mutex_);

  routes_[pref.getNetworkAddressType()].erase(routes_[pref.getNetworkAddressType()].find(pref));
}

uint16_t RoutingTable::getRoute(const NetworkAddress& addr)
{
  Lock lock(mutex_);
  network_address_type_t type=addr.getNetworkAddressType();

  if(routes_[type].empty()) {
    AnytunError::throwErr() << "no route";
  }

  if(type==ipv4) {
    ipv4_bytes_type bytes(addr.to_bytes_v4());
    return RoutingTree::find(bytes, root_[type]);
  } else if(type==ipv6) {
    ipv6_bytes_type bytes(addr.to_bytes_v6());
    return RoutingTree::find(bytes, root_[type]);
  } else if(type==ethernet) {
    //TODO Our model wont fit to ethernet addresses well.
    // maybe use hashmap or something like that instead
    ethernet_bytes_type bytes(addr.to_bytes_ethernet());
    return RoutingTree::find(bytes, root_[type]);
  } else {
    AnytunError::throwErr() << "illegal protocol type";
  }
  return 0;
}

uint16_t* RoutingTable::getOrNewRoutingTEUnlocked(const NetworkPrefix& addr)
{
  RoutingMap::iterator it = routes_[addr.getNetworkAddressType()].find(addr);
  if(it!=routes_[addr.getNetworkAddressType()].end()) {
    return &(it->second);
  }

  routes_[addr.getNetworkAddressType()].insert(RoutingMap::value_type(addr, 1));
  it = routes_[addr.getNetworkAddressType()].find(addr);
  return &(it->second);
}

uint16_t RoutingTable::getCountUnlocked(network_address_type_t type)
{
  RoutingMap::iterator it = routes_[type].begin();
  uint16_t routes=0;
  for(; it!=routes_[type].end(); ++it) {
    routes++;
  }
  return routes;
}

RoutingMap::iterator RoutingTable::getBeginUnlocked(network_address_type_t type)
{
  return routes_[type].begin();
}

RoutingMap::iterator RoutingTable::getEndUnlocked(network_address_type_t type)
{
  return routes_[type].end();
}

void RoutingTable::clear(network_address_type_t type)
{
  Lock lock(mutex_);
  routes_[type].clear();
}

bool RoutingTable::empty(network_address_type_t type)
{
  Lock lock(mutex_);
  return routes_[type].empty();
}

Mutex& RoutingTable::getMutex()
{
  return mutex_;
}
