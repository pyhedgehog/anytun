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

#include <csignal>
#include <map>

#include <iostream>

#include "threadUtils.hpp"
#include "signalController.h"
#include "log.h"


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

SignalController::~SignalController() 
{
  for(HandlerMap::iterator it = handler.begin(); it != handler.end(); ++it)
    delete it->second;
}

void* SignalController::handle(void *s)
{
  SignalController* self = reinterpret_cast<SignalController*>(s);
  sigset_t signal_set;
  int sigNum;

  while(1) 
  {
    sigfillset(&signal_set);
    sigwait(&signal_set, &sigNum);
    {
      Lock(self->sigQueueMutex);
      self->sigQueue.push(sigNum);
    }
    self->sigQueueSem.up();
  }
  pthread_exit(NULL);
}

void SignalController::init()
{
  sigset_t signal_set;
  
  sigfillset(&signal_set);        
  sigdelset(&signal_set, SIGCHLD);
  sigdelset(&signal_set, SIGSEGV);
  sigdelset(&signal_set, SIGBUS);
  sigdelset(&signal_set, SIGFPE);
  pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

  pthread_create(&thread, NULL, handle, this);  
  pthread_detach(thread);

  handler[SIGINT] = new SigIntHandler;
  handler[SIGQUIT] = new SigQuitHandler;
  handler[SIGHUP] = new SigHupHandler;
  handler[SIGTERM] = new SigTermHandler;
  handler[SIGUSR1] = new SigUsr1Handler;
  handler[SIGUSR2] = new SigUsr2Handler;
}

int SignalController::run()
{
  while(1) 
  {
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
