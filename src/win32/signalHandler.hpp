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

class CtrlCHandler : public SignalHandler
{
public:
  CtrlCHandler() : SignalHandler(CTRL_C_EVENT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "CTRL-C Event received, exitting";
    return 1;
  }
};

class CtrlBreakHandler : public SignalHandler
{
public:
  CtrlBreakHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "CTRL-Break Event received, ignoring";
    return 0;
  }
};

class CtrlCloseHandler : public SignalHandler
{
public:
  CtrlCloseHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "Close Event received, exitting";
    return 1;
  }
};

class CtrlLogoffHandler : public SignalHandler
{
public:
  CtrlLogoffHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "LogOff Event received, exitting";
    return 1;
  }
};

class CtrlShutdownHandler : public SignalHandler
{
public:
  CtrlShutdownHandler() : SignalHandler(CTRL_BREAK_EVENT) {}
  int handle()
  {
    cLog.msg(Log::PRIO_NOTICE) << "Shutdown Event received, exitting";
    return 1;
  }
};

bool handle(DWORD ctrlType)
{
  gSignalController.inject(ctrlType);
  return true;
}

void registerSignalHandler(SignalController& ctrl)
{
  if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)handle, true))
    AnytunError::throwErr() << "Error on SetConsoleCtrlhandler: " << AnytunErrno(GetLastError());

  handler[CTRL_C_EVENT] = new CtrlCHandler;
  handler[CTRL_BREAK_EVENT] = new CtrlBreakHandler;
  handler[CTRL_CLOSE_EVENT] = new CtrlCloseHandler;
  handler[CTRL_LOGOFF_EVENT] = new CtrlLogoffHandler;
  handler[CTRL_SHUTDOWN_EVENT] = new CtrlShutdownHandler;
}

#endif
