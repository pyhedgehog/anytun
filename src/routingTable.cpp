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
#include "networkPrefix.h"
#include "threadUtils.hpp"
#include "datatypes.h"

#include "routingTable.h"

RoutingTable* RoutingTable::inst = NULL;
Mutex RoutingTable::instMutex;
RoutingTable& gRoutingTable = RoutingTable::instance();


RoutingTable& RoutingTable::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new RoutingTable();

  return *inst;
}

RoutingTable::RoutingTable()
{
}

RoutingTable::~RoutingTable()
{
} 

void RoutingTable::addRoute(const NetworkPrefix & pref,u_int16_t mux )
{
  Lock lock(mutex_);
	
	
  std::pair<RoutingMap::iterator, bool> ret = routes_.insert(RoutingMap::value_type(pref,mux));
  if(!ret.second)
  {
    routes_.erase(ret.first);
    routes_.insert(RoutingMap::value_type(pref,mux));
  }
}


void RoutingTable::delRoute(const NetworkPrefix & pref )
{
  Lock lock(mutex_);
	
  routes_.erase(routes_.find(pref));	
}

u_int16_t  RoutingTable::getRoute(const NetworkAddress & addr)
{
	Lock lock(mutex_);
	if (routes_.empty())
  	return 0;
	NetworkPrefix prefix(addr,32);
	//TODO Routing algorithem isnt working!!!
	RoutingMap::iterator it = routes_.lower_bound(prefix);
//	it--;
	if (it!=routes_.end())
		return it->second;
	it=routes_.begin();
	return it->second;
}

u_int16_t* RoutingTable::getOrNewRoutingTEUnlocked(const NetworkPrefix & addr)
{
  RoutingMap::iterator it = routes_.find(addr);
  if(it!=routes_.end())
    return &(it->second);

  routes_.insert(RoutingMap::value_type(addr, 1));
  it = routes_.find(addr);
  return &(it->second);
}

u_int16_t RoutingTable::getCountUnlocked()
{
	RoutingMap::iterator it = routes_.begin();
	u_int16_t routes=0;
	for (;it!=routes_.end();++it)
		routes++;
	return routes;
}

RoutingMap::iterator RoutingTable::getBeginUnlocked()
{
	return routes_.begin();
}

RoutingMap::iterator RoutingTable::getEndUnlocked()
{
	return routes_.end();
}

void RoutingTable::clear()
{
  Lock lock(mutex_);
	routes_.clear();
}

bool RoutingTable::empty()
{
  Lock lock(mutex_);
	return routes_.empty();
}

Mutex& RoutingTable::getMutex()
{
  return mutex_;
}
