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

#include <windows.h>

int CtrlCHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "CTRL-C Event received, exitting";
  return 1;
}

int CtrlBreakHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "CTRL-Break Event received, ignoring";
  return 0;
}

int CtrlCloseHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "Close Event received, exitting";
  return 1;
}

int CtrlLogoffHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "LogOff Event received, exitting";
  return 1;
}

int CtrlShutdownHandler(int /*sig*/, const std::string& /*msg*/)
{
  cLog.msg(Log::PRIO_NOTICE) << "Shutdown Event received, exitting";
  return 1;
}

bool handleSignal(DWORD ctrlType)
{
  gSignalController.inject(ctrlType);
  return true;
}

void registerSignalHandler(SignalController& ctrl, DaemonService* /*service*/)
{
  if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)handleSignal, true))
    AnytunError::throwErr() << "Error on SetConsoleCtrlhandler: " << AnytunErrno(GetLastError());

  ctrl.handler[CTRL_C_EVENT] = boost::bind(CtrlCHandler, _1, _2);
  ctrl.handler[CTRL_BREAK_EVENT] = boost::bind(CtrlBreakHandler, _1, _2);
  ctrl.handler[CTRL_CLOSE_EVENT] = boost::bind(CtrlCloseHandler, _1, _2);
  ctrl.handler[CTRL_LOGOFF_EVENT] = boost::bind(CtrlLogoffHandler, _1, _2);
  ctrl.handler[CTRL_SHUTDOWN_EVENT] = boost::bind(CtrlShutdownHandler, _1, _2);
}

#endif
