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

#ifndef _SYNC_QUEUE_H
#define _SYNC_QUEUE_H

#include <deque>
#include <queue>

#include "syncCommand.h"

#include "threadUtils.hpp"
#include "datatypes.h"

class SyncQueue
{
public:
	SyncQueue() {};
	~SyncQueue() {};

	void push(const std::string & );
	void push(const SyncCommand & );
	std::string pop();
	bool empty();

private:
  SyncQueue(const SyncQueue &s);
  void operator=(const SyncQueue &s);
	typedef std::queue<std::string> StringQueue;
	StringQueue queue_;
  Mutex mutex_;
};

#endif