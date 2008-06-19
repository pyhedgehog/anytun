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
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#ifndef __THREADUTILS__
#define __THREADUTILS__
typedef boost::mutex::scoped_lock Lock;
typedef boost::mutex Mutex;

class Semaphore
{
public:
  Semaphore(unsigned int initVal=0)
    :count_(initVal){};
  void up()
  {
     boost::mutex::scoped_lock lock(mutex_);
     count_++;
     lock.unlock();
     cond_.notify_one();
  }
  void down()
  {
     boost::mutex::scoped_lock lock(mutex_);
     while (count_ <= 0)
       cond_.wait(lock);
     count_--;
  }
private:
  boost::mutex mutex_;
  boost::condition cond_;
  int16_t count_;
};

#endif
