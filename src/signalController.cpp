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

#include <map>
#include <iostream>

#include "signalController.h"
#include "log.h"
#include "anytunError.h"
#include "threadUtils.hpp"


SignalController* SignalController::inst = NULL;
Mutex SignalController::instMutex;
SignalController& gSignalController = SignalController::instance();

SignalController& SignalController::instance()
{
	Lock lock(instMutex);
	static instanceCleaner c;
	if(!inst)
		inst = new SignalController();

	return *inst;
}

int SigErrorHandler::handle(const std::string& msg)
{
  AnytunError::throwErr() << msg;

  return 0;
}

// use system specific signal handler
#ifndef _MSC_VER
#include "signalHandler.hpp"
#else
#include "win32/signalHandler.hpp"
#endif

SignalController::~SignalController() 
{
  for(HandlerMap::iterator it = handler.begin(); it != handler.end(); ++it)
    delete it->second;
}

void SignalController::init()
{
  registerSignalHandler(*this);
  handler[SIGERROR] = new SigErrorHandler;
}

void SignalController::inject(int sig, const std::string& msg)
{
  {
    Lock lock(sigQueueMutex);
    sigQueue.push(SigPair(sig, msg));
  }
  sigQueueSem.up();
}

int SignalController::run()
{
  while(1) {
    sigQueueSem.down();
    SigPair sig;
    {
      Lock lock(sigQueueMutex);
      sig = sigQueue.front();
      sigQueue.pop();
    }
    
    HandlerMap::iterator it = handler.find(sig.first);
    if(it != handler.end())
    {
      int ret;
      if(sig.second == "")
        ret = it->second->handle();
      else
        ret = it->second->handle(sig.second);

      if(ret)
        return ret;
    }
    else
      cLog.msg(Log::PRIO_NOTICE) << "SIG " << sig.first << " caught with message '" << sig.second << "' - ignoring";
  }
  return 0;
}

