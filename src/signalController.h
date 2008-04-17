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

#ifndef _SIGNAL_CONTROLLER_H_
#define _SIGNAL_CONTROLLER_H_

#include <csignal>
#include <map>
#include <queue>

#include "threadUtils.hpp"

class SignalHandler
{
public:
  virtual ~SignalHandler() {}

  virtual int handle() { return 0; }

protected:
  SignalHandler(int s) : sigNum(s) {}

private:
  int sigNum;
  friend class SignalController;
};

class SigIntHandler : public SignalHandler
{
public:
  SigIntHandler() : SignalHandler(SIGINT) {}
  int handle();
};

class SigQuitHandler : public SignalHandler
{
public:
  SigQuitHandler() : SignalHandler(SIGQUIT) {}
  int handle();
};

class SigHupHandler : public SignalHandler
{
public:
  SigHupHandler() : SignalHandler(SIGHUP) {}
  int handle();
};

class SigUsr1Handler : public SignalHandler
{
public:
  SigUsr1Handler() : SignalHandler(SIGUSR1) {}
  int handle();
};

class SigUsr2Handler : public SignalHandler
{
public:
  SigUsr2Handler() : SignalHandler(SIGUSR2) {}
  int handle();
};

class SigTermHandler : public SignalHandler
{
public:
  SigTermHandler() : SignalHandler(SIGTERM) {}
  int handle();
};

class SignalController
{
public:
  SignalController() {}
  ~SignalController();
  static void* handle(void* s);

  void init();
  int run();

private:
  typedef std::map<int, SignalHandler*> HandlerMap;

  SignalController(const SignalController &s);
  void operator=(const SignalController &s);
  
  std::queue<int> sigQueue;
  Mutex sigQueueMutex;
  Semaphore sigQueueSem;

  pthread_t thread;
  HandlerMap handler;
};

#endif