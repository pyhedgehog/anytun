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

#ifndef _THREADUTILS_HPP_
#define _THREADUTILS_HPP_

#include <stdexcept>
#include <semaphore.h>

class Mutex 
{
public:
  Mutex() 
  { 
    if(pthread_mutex_init(&mutex,NULL)) 
      throw std::runtime_error("can't create mutex");
  }

  ~Mutex()
  {
    pthread_mutex_destroy(&mutex);
  }
  
private:
  Mutex(const Mutex& src);
  void operator=(const Mutex& src);
  
  void lock()
  {
    if(pthread_mutex_lock(&mutex)) 
      throw std::runtime_error("can't lock mutex");
  }
  
  void unlock()
  {
    if(pthread_mutex_unlock(&mutex)) 
      throw std::runtime_error("can't unlock mutex");
  }
  friend class Lock;
  friend class Condition;
  pthread_mutex_t mutex;
};


class Lock
{
public:
  Lock(Mutex &m) : mutex(m)
  {
    mutex.lock();
  }
  
  ~Lock()
  {
    mutex.unlock();
  }

private:
  Lock(const Lock& src);
  void operator=(const Lock& src);

  Mutex &mutex;
};

class Condition
{
public:
  Condition()
  {
    if(pthread_cond_init(&cond, NULL)) 
      throw std::runtime_error("can't create condition");
  }

  ~Condition()
  {
    pthread_cond_destroy(&cond);
  }
  
  void wait()
  {
    mutex.lock();
    if(pthread_cond_wait(&cond, &mutex.mutex)) 
    {
      mutex.unlock();
      throw std::runtime_error("error on waiting for condition");
    }
    mutex.unlock();
  }

  void signal()
  {
    mutex.lock();
    if(pthread_cond_signal(&cond)) 
    {
      mutex.unlock();
      throw std::runtime_error("can't signal condition");
    }
    mutex.unlock();
  }

  void broadcast()
  {
    mutex.lock();
    if(pthread_cond_broadcast(&cond)) 
    {
      mutex.unlock();
      throw std::runtime_error("can't broadcast condition");
    }
    mutex.unlock();
  }
  
private:
  pthread_cond_t cond;
  Mutex mutex;
};

class Semaphore
{
public:
  Semaphore(unsigned int initVal=0)
  {
    if(sem_init(&sem, 0, initVal))
      throw std::runtime_error("can't create semaphore");
  }

  ~Semaphore()
  {
    sem_destroy(&sem);
  }
  
  void down()
  {
    if(sem_wait(&sem)) 
      throw std::runtime_error("error on semaphore down");
  }

  void up()
  {
    if(sem_post(&sem)) 
      throw std::runtime_error("error on semaphore up");
  }

private:
  sem_t sem;
};

#endif
