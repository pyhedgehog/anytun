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

#ifndef ANYTUN_signalController_h_INCLUDED
#define ANYTUN_signalController_h_INCLUDED

#include <map>
#include <queue>

#include "threadUtils.hpp"

#ifndef _MSC_VER
#include <csignal>
#endif

#define SIGERROR -1

class SignalHandler
{
public:
  virtual ~SignalHandler() {}

  virtual int handle() { return 0; }
  virtual int handle(const std::string& msg) { return 0; }

protected:
  SignalHandler(int s) : sigNum(s) {}

private:
  int sigNum;
  friend class SignalController;
};

class SigErrorHandler : public SignalHandler
{
public:
  SigErrorHandler() : SignalHandler(SIGERROR) {}
  int handle(const std::string& msg);
};

#ifndef _MSC_VER
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

#else

class CtrlCHandler : public SignalHandler
{
public:
  CtrlCHandler() : SignalHandler(CTRL_C_EVENT) {}
  int handle();
};

class CtrlBreakHandler : public SignalHandler
{
public:
  CtrlBreakHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle();
};

class CtrlCloseHandler : public SignalHandler
{
public:
  CtrlCloseHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle();
};

class CtrlLogoffHandler : public SignalHandler
{
public:
  CtrlLogoffHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle();
};

class CtrlShutdownHandler : public SignalHandler
{
public:
  CtrlShutdownHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle();
};
#endif

class SignalController
{
public:
  static SignalController& instance();
#ifndef _MSC_VER
  void handle();
#else
  static bool handle(DWORD ctrlType);
#endif

  void init();
  int run();
  void inject(int sig, const std::string& msg = "");

private:
  typedef std::map<int, SignalHandler*> HandlerMap;

  SignalController() {};
  ~SignalController();
  SignalController(const SignalController &s);
  void operator=(const SignalController &s);

  static SignalController* inst;
  static Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(SignalController::inst != NULL)
        delete SignalController::inst;
    }
  };
  friend class instanceCleaner;

  typedef std::pair<int, std::string> SigPair;
  std::queue<SigPair> sigQueue;
  Mutex sigQueueMutex;
  Semaphore sigQueueSem;

  HandlerMap handler;
};

extern SignalController& gSignalController;

#endif
