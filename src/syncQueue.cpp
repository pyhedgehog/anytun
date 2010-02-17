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

#include "threadUtils.hpp"
#include "datatypes.h"

#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "syncQueue.h"

SyncQueue* SyncQueue::inst = NULL;
Mutex SyncQueue::instMutex;
SyncQueue& gSyncQueue = SyncQueue::instance();


SyncQueue& SyncQueue::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst) {
    inst = new SyncQueue();
  }

  return *inst;
}

void SyncQueue::push(const SyncCommand& scom)
{
  std::ostringstream sout;
  boost::archive::text_oarchive oa(sout);
  oa << scom;

  std::stringstream lengthout;
  lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
  push(lengthout.str()+sout.str());
}

void SyncQueue::push(const std::string& str)
{
  Lock lock(mutex_);
  //	std::cout << "Debug" << std:endl;
  if(syncServer_) {
    syncServer_->send(str);
  }
}

void SyncQueue::setSyncServerPtr(SyncServer* ptr)
{
  Lock lock(mutex_);
  syncServer_=ptr;
}

bool SyncQueue::empty()
{
  Lock lock(mutex_);
  return 1;
}
