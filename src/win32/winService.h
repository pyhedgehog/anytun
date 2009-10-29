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

#ifndef _WIN_SERVICE_H_
#define _WIN_SERVICE_H_

#ifdef WIN_SERVICE

#include "../threadUtils.hpp"

class WinService
{
public:
  static WinService& instance();
  #define SVC_NAME "anytun"
  static void install();
  static void uninstall();
  static void start();

  void waitForStop();
  void stop();

  static VOID WINAPI main(DWORD dwArgc, LPTSTR *lpszArgv);
  static VOID WINAPI ctrlHandler(DWORD dwCtrl);
private:
  WinService() : started_(false) {};
  ~WinService();
  WinService(const WinService &w);
  void operator=(const WinService &w);

  void reportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint=0);

  static WinService* inst;
  static Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(WinService::inst != NULL)
        delete WinService::inst;
    }
  };
  friend class instanceCleaner;
  
  bool started_;
  SERVICE_STATUS status_;
  SERVICE_STATUS_HANDLE status_handle_;
  HANDLE stop_event_;
};

extern WinService& gWinService;

#endif

#endif