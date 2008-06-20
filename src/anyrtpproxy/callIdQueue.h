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
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CALLID_QUEUE_H__
#define __CALLID_QUEUE_H__

#include <queue>
#include <string>

#include "../threadUtils.hpp"

class CallIdQueue
{
public:
  static CallIdQueue& instance(); 
  
  std::string& front();
  void push(std::string c);
  void pop();

private:
  CallIdQueue();
  ~CallIdQueue();

  void operator=(const CallIdQueue &src);
  CallIdQueue(const CallIdQueue &src);

  static CallIdQueue* inst;
  static ::Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(CallIdQueue::inst != 0)
        delete CallIdQueue::inst;
    }
  };
  friend class instanceCleaner;

  ::Mutex mutex_;
  Semaphore sem_;
  std::queue<std::string> callids_;
};

extern CallIdQueue& gCallIdQueue;

#endif
