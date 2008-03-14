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
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

void RtpSessionTable::addSession(const std::string & call_id, RtpSession* ses )
{
  Lock lock(mutex_);
	
	
  std::pair<RtpSessionMap::iterator, bool> ret = map_.insert(RtpSessionMap::value_type(call_id,ses));
  if(!ret.second)
  {
    map_.erase(ret.first);
    map_.insert(RtpSessionMap::value_type(call_id,ses));
  }
}


void RtpSessionTable::delSession(const std::string & call_id )
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
  map_.insert(RtpSessionMap::value_type(call_id, new RtpSession()));
  it = map_.find(call_id);
  return *(it->second);
}

RtpSession& RtpSessionTable::getSession(const std::string & call_id)
{
  RtpSessionMap::iterator it = map_.find(call_id);
  if(it!=map_.end())
    return *(it->second);

  throw std::runtime_error("session not found");
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
