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

#ifndef NO_SIGNALCONTROLLER

#include <map>
#include <iostream>

#include "signalController.h"
#include "log.h"
#include "anytunError.h"
#include "threadUtils.hpp"

#ifndef _MSC_VER
#include <csignal>
#include <boost/bind.hpp>
#else
#include <windows.h>
#endif

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

#ifndef _MSC_VER

int SigIntHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Int caught, exiting";

  return 1;
}

int SigQuitHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Quit caught, exiting";

  return 1;
}

int SigHupHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Hup caught";

  return 0;
}

int SigTermHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Term caughtm, exiting";

  return 1;
}

int SigUsr1Handler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr1 caught";

  return 0;
}

int SigUsr2Handler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr2 caught";

  return 0;
}
#else
int CtrlCHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "CTRL-C Event received, exitting";

  return 1;
}

int CtrlBreakHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "CTRL-Break Event received, ignoring";

  return 0;
}

int CtrlCloseHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "Close Event received, exitting";

  return 1;
}

int CtrlLogoffHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "LogOff Event received, exitting";

  return 1;
}

int CtrlShutdownHandler::handle()
{
  cLog.msg(Log::PRIO_NOTICE) << "Shutdown Event received, exitting";

  return 1;
}
#endif

SignalController::~SignalController() 
{
  for(HandlerMap::iterator it = handler.begin(); it != handler.end(); ++it)
    delete it->second;

#ifndef _MSC_VER
  if(thread) delete thread;
#endif
}

#ifndef _MSC_VER
void SignalController::handle()
{
  sigset_t signal_set;
  int sigNum;

  while(1) 
  {
    sigfillset(&signal_set);
    sigwait(&signal_set, &sigNum);
    inject(sigNum);
  }
}
#else
bool SignalController::handle(DWORD ctrlType)
{
  gSignalController.inject(ctrlType);
  return true;
}
#endif

void SignalController::init()
{
#ifndef _MSC_VER
  sigset_t signal_set;
  
  sigfillset(&signal_set);        
  sigdelset(&signal_set, SIGCHLD);
  sigdelset(&signal_set, SIGSEGV);
  sigdelset(&signal_set, SIGBUS);
  sigdelset(&signal_set, SIGFPE);

#if defined(BOOST_HAS_PTHREADS)
  pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
#else
#error The signalhandler works only with pthreads
#endif
  
  thread = new boost::thread(boost::bind(&SignalController::handle, this));

  handler[SIGINT] = new SigIntHandler;
  handler[SIGQUIT] = new SigQuitHandler;
  handler[SIGHUP] = new SigHupHandler;
  handler[SIGTERM] = new SigTermHandler;
  handler[SIGUSR1] = new SigUsr1Handler;
  handler[SIGUSR2] = new SigUsr2Handler;
#else
  if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)SignalController::handle, true))
    AnytunError::throwErr() << "Error on SetConsoleCtrlhandler: " << AnytunErrno(GetLastError());

  handler[CTRL_C_EVENT] = new CtrlCHandler;
  handler[CTRL_BREAK_EVENT] = new CtrlBreakHandler;
  handler[CTRL_CLOSE_EVENT] = new CtrlCloseHandler;
  handler[CTRL_LOGOFF_EVENT] = new CtrlLogoffHandler;
  handler[CTRL_SHUTDOWN_EVENT] = new CtrlShutdownHandler;
#endif
}

void SignalController::inject(int sig)
{
  {
    Lock lock(sigQueueMutex);
    sigQueue.push(sig);
  }
  sigQueueSem.up();
}

int SignalController::run()
{
  while(1) {
    sigQueueSem.down();
    int sigNum;
    {
      Lock lock(sigQueueMutex);
      sigNum = sigQueue.front();
      sigQueue.pop();
    }
    
    HandlerMap::iterator it = handler.find(sigNum);
    if(it != handler.end())
    {
      int ret = it->second->handle();
      if(ret)
        return ret;
    }
    else
      cLog.msg(Log::PRIO_NOTICE) << "SIG " << sigNum << " caught - ignoring";
  }
  return 0;
}

#endif
