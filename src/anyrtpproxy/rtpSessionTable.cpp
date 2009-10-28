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
#include "../threadUtils.hpp"
#include "../datatypes.h"

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

void RtpSessionTable::delSession(const std::string & call_id)
{
  Lock lock(mutex_);

  RtpSessionMap::iterator it = map_.find(call_id);
  if(it!=map_.end())
    delete it->second;

  map_.erase(it);
}

RtpSession& RtpSessionTable::getOrNewSession(const std::string & call_id, bool& is_new)
{
  Lock lock(mutex_);
  return getOrNewSessionUnlocked(call_id, is_new);
}

RtpSession& RtpSessionTable::getOrNewSessionUnlocked(const std::string & call_id, bool& is_new)
{
  is_new = false;
  RtpSessionMap::iterator it = map_.find(call_id);
  if(it!=map_.end())
    return *(it->second);

  is_new = true;
  std::pair<RtpSessionMap::iterator, bool> ret = map_.insert(RtpSessionMap::value_type(call_id, NULL));
  ret.first->second = new RtpSession(ret.first->first);
  return *(ret.first->second);
}

RtpSession& RtpSessionTable::getSession(const std::string & call_id)
{
  RtpSessionMap::iterator it = map_.find(call_id);
  if(it!=map_.end())
    return *(it->second);

  throw std::runtime_error("session not found");
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
