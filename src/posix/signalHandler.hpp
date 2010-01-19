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

#ifndef ANYTUN_signalHandler_h_INCLUDED
#define ANYTUN_signalHandler_h_INCLUDED

#include <csignal>
#include <boost/thread.hpp>
#include <boost/bind.hpp>

class SigIntHandler : public SignalHandler
{
public:
  SigIntHandler() : SignalHandler(SIGINT) {}
  int handle() 
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Int caught, exiting";
    return 1;
  }
};

class SigQuitHandler : public SignalHandler
{
public:
  SigQuitHandler() : SignalHandler(SIGQUIT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Quit caught, exiting";
    return 1;
  }
};

class SigHupHandler : public SignalHandler
{
public:
  SigHupHandler() : SignalHandler(SIGHUP) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Hup caught"; 
    return 0;
  }
};

class SigUsr1Handler : public SignalHandler
{
public:
  SigUsr1Handler() : SignalHandler(SIGUSR1) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Term caught, exiting";
    return 1;
  }
};

class SigUsr2Handler : public SignalHandler
{
public:
  SigUsr2Handler() : SignalHandler(SIGUSR2) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr1 caught";
    return 0;
  }
};

class SigTermHandler : public SignalHandler
{
public:
  SigTermHandler() : SignalHandler(SIGTERM) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr2 caught";
    return 0;
  }
};

void handle()
{
  sigset_t signal_set;
  int sigNum;
  int err = 0;
  while(1) {
    sigfillset(&signal_set);
    err = sigwait(&signal_set, &sigNum);
    if (err) {
      if (err != EINTR && errno != EINTR ) {
      	cLog.msg(Log::PRIO_ERROR) << "sigwait failed with error: \"" << AnytunErrno(errno) << "\" SignalHandling will be disabled";
      	break;
      }
    } else {
      gSignalController.inject(sigNum);
    }
  }
}

void registerSignalHandler(SignalController& ctrl)
{
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
  
  boost::thread(boost::bind(handle));

  ctrl.handler[SIGINT] = new SigIntHandler;
  ctrl.handler[SIGQUIT] = new SigQuitHandler;
  ctrl.handler[SIGHUP] = new SigHupHandler;
  ctrl.handler[SIGTERM] = new SigTermHandler;
  ctrl.handler[SIGUSR1] = new SigUsr1Handler;
  ctrl.handler[SIGUSR2] = new SigUsr2Handler;

  cLog.msg(Log::PRIO_DEBUG) << "signal handlers are now registered";
}

#endif
