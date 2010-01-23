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

int SigIntHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Int caught, exiting";
  return 1;
}

int SigQuitHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Quit caught, exiting";
  return 1;
}

int SigHupHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Hup caught"; 
  return 0;
}

int SigTermHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Term caught, exiting";
  return 1;
}

int SigUsr1Handler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr1 caught";
  return 0;
}

int SigUsr2Handler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "SIG-Usr2 caught";
  return 0;
}

void handleSignal()
{
  struct timespec timeout;
  sigset_t signal_set;
  int sigNum;
  while(1) {
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigaddset(&signal_set, SIGQUIT);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);
    sigaddset(&signal_set, SIGUSR2);
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    sigNum = sigtimedwait(&signal_set, NULL, &timeout);
    if (sigNum == -1) {
      if (errno != EINTR && errno != EAGAIN) {
      	cLog.msg(Log::PRIO_ERROR) << "sigwait failed with error: \"" << AnytunErrno(errno) << "\" SignalHandling will be disabled";
      	break;
      }
    } else {
      gSignalController.inject(sigNum);
    }
  }
}

void registerSignalHandler(SignalController& ctrl, DaemonService* /*service*/)
{
  sigset_t signal_set;
  
  sigemptyset(&signal_set);
  sigaddset(&signal_set, SIGINT);
  sigaddset(&signal_set, SIGQUIT);
  sigaddset(&signal_set, SIGHUP);
  sigaddset(&signal_set, SIGTERM);
  sigaddset(&signal_set, SIGUSR1);
  sigaddset(&signal_set, SIGUSR2);
  
#if defined(BOOST_HAS_PTHREADS)
  pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
#else
#error The signalhandler works only with pthreads
#endif
  
  boost::thread(boost::bind(handleSignal));

  ctrl.handler[SIGINT] = boost::bind(SigIntHandler, _1, _2);
  ctrl.handler[SIGQUIT] = boost::bind(SigQuitHandler, _1, _2);
  ctrl.handler[SIGHUP] = boost::bind(SigHupHandler, _1, _2);
  ctrl.handler[SIGTERM] = boost::bind(SigTermHandler, _1, _2);
  ctrl.handler[SIGUSR1] = boost::bind(SigUsr1Handler, _1, _2);
  ctrl.handler[SIGUSR2] = boost::bind(SigUsr2Handler, _1, _2);

  cLog.msg(Log::PRIO_DEBUG) << "signal handlers are now registered";
}

#endif
