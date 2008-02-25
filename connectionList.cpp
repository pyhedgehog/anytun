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
#include "keyDerivationFactory.h"
#include "options.h"

#include "connectionList.h"

ConnectionList::ConnectionList()
{
}

ConnectionList::~ConnectionList()
{
/*  Lock lock(mutex_);
	ConnectionMap::iterator it;
	for(it = connections_.begin(); it != connections_.end(); ++it)
	{
		//delete &it->second.kd_;
	}
*/
} 

void ConnectionList::addConnection(ConnectionParam &conn, u_int16_t mux )
{
  Lock lock(mutex_);

  std::pair<ConnectionMap::iterator, bool> ret = connections_.insert(ConnectionMap::value_type(mux, conn));
  if(!ret.second)
  {
    connections_.erase(ret.first);
    connections_.insert(ConnectionMap::value_type(mux, conn));
  }
}

const ConnectionMap::iterator ConnectionList::getEnd()
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
	if(it!=connections_.end())
		return it->second;

  uint8_t key[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'
  };
  
  uint8_t salt[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'l', 'm', 'n'
  };

  SeqWindow * seq= new SeqWindow(0);
  seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(Buffer(key, sizeof(key)), Buffer(salt, sizeof(salt)));
  ConnectionParam conn ( (*kd),  (*seq), seq_nr_, "",  0);
	connections_.insert(ConnectionMap::value_type(mux, conn));
	it = connections_.find(mux);
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
