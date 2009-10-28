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

#include "connectionList.h"

ConnectionList::ConnectionList()
{
}

ConnectionList::~ConnectionList()
{
} 

void ConnectionList::addConnection(ConnectionParam &conn, u_int16_t mux )
{
}

const ConnectionMap::iterator ConnectionList::getEnd()
{
	return connections_.end();
}

ConnectionMap::iterator ConnectionList::getBeginUnlocked()
{
  return connections_.begin();
}

ConnectionMap::iterator ConnectionList::getEndUnlocked()
{
  return connections_.end();
}

const ConnectionMap::iterator ConnectionList::getConnection(u_int16_t mux)
{
	Lock lock(mutex_);
	ConnectionMap::iterator it = connections_.find(mux);
	return it;
}


ConnectionParam & ConnectionList::getOrNewConnectionUnlocked(u_int16_t mux)
{
	ConnectionMap::iterator it = connections_.find(mux);
		return it->second;
}

void ConnectionList::clear()
{
  Lock lock(mutex_);
	connections_.clear();
}

bool ConnectionList::empty()
{
  Lock lock(mutex_);
	return connections_.empty();
}

Mutex& ConnectionList::getMutex()
{
  return mutex_;
}
