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

#ifndef _CONNECTION_LIST_H
#define _CONNECTION_LIST_H

#include <map>

#include "../threadUtils.hpp"
#include "../datatypes.h"
#include "../connectionParam.h"
#include "../networkAddress.h"
typedef std::map<u_int16_t, ConnectionParam> ConnectionMap;

class ConnectionList
{
public:
	ConnectionList();
	~ConnectionList();
	void addConnection(ConnectionParam &conn, u_int16_t mux);
	const ConnectionMap::iterator getConnection(u_int16_t mux);
	const ConnectionMap::iterator getEnd();
	ConnectionMap::iterator getEndUnlocked();
	ConnectionMap::iterator getBeginUnlocked();
	ConnectionParam & getOrNewConnectionUnlocked(u_int16_t mux);
	bool empty();
	void clear();
  Mutex& getMutex();

private:
  ConnectionList(const ConnectionList &s);
  void operator=(const ConnectionList &s);
	ConnectionMap connections_;
  Mutex mutex_;
};

#endif
