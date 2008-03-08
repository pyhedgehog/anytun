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
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "threadUtils.hpp"
#include "datatypes.h"

#include "rtpSessionTable.h"

RtpSessionTable* RtpSessionTable::inst = NULL;
Mutex RtpSessionTable::instMutex;
RtpSessionTable& gRtpSessionTable = RtpSessionTable::instance();


RtpSessionTable& RtpSessionTable::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new RtpSessionTable();

  return *inst;
}

RtpSessionTable::RtpSessionTable()
{
}

RtpSessionTable::~RtpSessionTable()
{
} 

void RtpSessionTable::addSession(const std::string & pref, const RtpSession & ses )
{
  Lock lock(mutex_);
	
	
  std::pair<RtpSessionMap::iterator, bool> ret = map_.insert(RtpSessionMap::value_type(pref,ses));
  if(!ret.second)
  {
    map_.erase(ret.first);
    map_.insert(RtpSessionMap::value_type(pref,ses));
  }
}


void RtpSessionTable::delSession(const std::string & pref )
{
  Lock lock(mutex_);
	
  map_.erase(map_.find(pref));	
}

/*u_int16_t  RtpSessionTable::getRtpSession(const std::string & addr)
{
	Lock lock(mutex_);
	if (map_.empty())
  	return 0;
	NetworkPrefix prefix(addr,32);
	//TODO Routing algorithem isnt working!!!
	RoutingMap::iterator it = map_.lower_bound(prefix);
//	it--;
	if (it!=map_.end())
		return it->second;
	it=map_.begin();
	return it->second;
}
*/

RtpSession& RtpSessionTable::getOrNewSessionUnlocked(const std::string & addr)
{
  RtpSessionMap::iterator it = map_.find(addr);
  if(it!=map_.end())
    return it->second;

  map_.insert(RtpSessionMap::value_type(addr, RtpSession()));
  it = map_.find(addr);
  return it->second;
}

uint16_t RtpSessionTable::getCountUnlocked()
{
	RtpSessionMap::iterator it = map_.begin();
	uint16_t routes=0;
	for (;it!=map_.end();++it)
		routes++;
	return routes;
}

RtpSessionMap::iterator RtpSessionTable::getBeginUnlocked()
{
	return map_.begin();
}

RtpSessionMap::iterator RtpSessionTable::getEndUnlocked()
{
	return map_.end();
}

void RtpSessionTable::clear()
{
  Lock lock(mutex_);
	map_.clear();
}

bool RtpSessionTable::empty()
{
  Lock lock(mutex_);
	return map_.empty();
}

Mutex& RtpSessionTable::getMutex()
{
  return mutex_;
}
