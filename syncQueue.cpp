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

#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "syncQueue.h"
void SyncQueue::push(const SyncCommand & scom )
{

  std::cout << "entered push" << std::endl;

	std::ostringstream sout;
	boost::archive::text_oarchive oa(sout);
	oa << scom;

  std::cout << "after serialize" << std::endl;

  Lock lock(mutex_);
	queue_.push(sout.str());
}

void SyncQueue::push(const std::string & str )
{
  Lock lock(mutex_);
	queue_.push(str);
}

std::string SyncQueue::pop()
{
	Lock lock(mutex_);
	std::string tmp = queue_.front();
	queue_.pop();
	return tmp;
}

bool SyncQueue::empty()
{
  Lock lock(mutex_);
	return queue_.empty();
}
