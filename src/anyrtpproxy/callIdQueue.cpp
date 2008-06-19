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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "callIdQueue.h"

CallIdQueue* CallIdQueue::inst = NULL;
Mutex CallIdQueue::instMutex;
CallIdQueue& gCallIdQueue = CallIdQueue::instance();

CallIdQueue& CallIdQueue::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new CallIdQueue();
  
  return *inst;
}

CallIdQueue::CallIdQueue()
{
}

CallIdQueue::~CallIdQueue()
{
  while(!callids_.empty())
    pop();
}

std::string& CallIdQueue::front()
{
  sem_.down();
  Lock lock(mutex_);
  return callids_.front();
}

void CallIdQueue::push(std::string c)
{
  Lock lock(mutex_);
  callids_.push(c);
  sem_.up();
}

void CallIdQueue::pop()
{
  Lock lock(mutex_);
  callids_.pop();
}

