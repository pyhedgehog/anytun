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
#include <boost/function.hpp>

#include "threadUtils.hpp"

#ifdef WIN_SERVICE
//#include "win32/winService.h"
class WinService;
typedef WinService DaemonService;
#else
class DaemonService;
#endif

#define SIGERROR -1
#define SIGUNKNOWN -2

typedef boost::function<int (int, std::string const&)> SignalHandler;
typedef enum { CALLB_RUNNING, CALLB_STOPPING } CallbackType;
typedef boost::function<void ()> ServiceCallback;

class SignalController
{
public:
  static SignalController& instance();

  void init(DaemonService& service);
  int run();
  void inject(int sig, const std::string& msg = "");

private:
  SignalController() {};
  ~SignalController() {};
  SignalController(const SignalController& s);
  void operator=(const SignalController& s);

  static SignalController* inst;
  static Mutex instMutex;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(SignalController::inst != NULL) {
        delete SignalController::inst;
      }
    }
  };
  friend class instanceCleaner;

  typedef std::pair<int, std::string> SigPair;
  std::queue<SigPair> sigQueue;
  Mutex sigQueueMutex;
  Semaphore sigQueueSem;

  typedef std::map<int, SignalHandler> HandlerMap;
  HandlerMap handler;
  typedef std::map<CallbackType, ServiceCallback> CallbackMap;
  CallbackMap callbacks;

  friend void registerSignalHandler(SignalController& ctrl, DaemonService& service);
};

extern SignalController& gSignalController;

#endif
