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

#ifdef WIN_SERVICE

#include <iostream>

#include <windows.h>

#include "winService.h"
#include "../log.h"
#include "../anytunError.h"
#include "../threadUtils.hpp"

void WinService::install()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  char szPath[MAX_PATH];

  if(!GetModuleFileNameA(NULL, szPath, MAX_PATH))
    AnytunError::throwErr() << "Error on GetModuleFileName: " << AnytunErrno(GetLastError());

  schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if(NULL == schSCManager)
    AnytunError::throwErr() << "Error on OpenSCManager: " << AnytunErrno(GetLastError());

  schService = CreateServiceA(schSCManager, SVC_NAME, SVC_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, 
                              SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
  if(schService == NULL) {
    CloseServiceHandle(schSCManager);
    AnytunError::throwErr() << "Error on CreateService: " << AnytunErrno(GetLastError());
  }

  std::cout << "Service installed successfully" << std::endl; 

  CloseServiceHandle(schService); 
  CloseServiceHandle(schSCManager);
}

void WinService::uninstall()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;

  schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if(NULL == schSCManager)
    AnytunError::throwErr() << "Error on OpenSCManager: " << AnytunErrno(GetLastError());

  schService = OpenServiceA(schSCManager, SVC_NAME, SERVICE_ALL_ACCESS);
  if(schService == NULL) {
    CloseServiceHandle(schSCManager);
    AnytunError::throwErr() << "Error on CreateService: " << AnytunErrno(GetLastError());
  }

  if(!DeleteService(schService)) {
    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
    AnytunError::throwErr() << "Error on DeleteService: " << AnytunErrno(GetLastError());
  }

  std::cout << "Service uninstalled successfully" << std::endl; 

  CloseServiceHandle(schService); 
  CloseServiceHandle(schSCManager);
}

void WinService::start()
{
  SERVICE_TABLE_ENTRY DispatchTable[] = {
    {SVC_NAME, (LPSERVICE_MAIN_FUNCTION)WinService::main },
    {NULL, NULL}
  };

  if(!StartServiceCtrlDispatcherA(DispatchTable))
    AnytunError::throwErr() << "Error on StartServiceCtrlDispatcher: " << AnytunErrno(GetLastError());
}

int real_main(int argc, char* argv[], WinService* service);

VOID WINAPI WinService::main(DWORD dwArgc, LPTSTR *lpszArgv)
{
  WinService service;

  service.status_handle_ = RegisterServiceCtrlHandlerA(SVC_NAME, WinService::ctrlHandler);
  if(!service.status_handle_) { 
    cLog.msg(Log::PRIO_ERROR) << "Error on RegisterServiceCtrlHandler: " << AnytunErrno(GetLastError());
    return;
  }
  service.status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
  service.status_.dwServiceSpecificExitCode = 0;    
  service.reportStatus(SERVICE_START_PENDING, NO_ERROR);
  
  real_main(dwArgc, lpszArgv, &service);
  
  service.reportStatus(SERVICE_STOPPED, NO_ERROR);
}

VOID WINAPI WinService::ctrlHandler(DWORD dwCtrl)
{
  gSignalController.inject(dwCtrl);
}

int WinService::handleCtrlSignal(int sig, const std::string& msg)
{
  switch(sig) {
    case SERVICE_CONTROL_STOP: {
      reportStatus(SERVICE_STOP_PENDING, NO_ERROR);
      cLog.msg(Log::PRIO_NOTICE) << "received service stop signal, exitting";
      return 1;
    }
    case SERVICE_CONTROL_INTERROGATE: break;
    default: break;
  }
  reportStatus(status_.dwCurrentState, NO_ERROR);

  return 0;
}

void WinService::reportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode)
{
  static DWORD dwCheckPoint = 1;

  status_.dwCurrentState = dwCurrentState;
  status_.dwWin32ExitCode = dwWin32ExitCode;
  status_.dwWaitHint = 0;

  if((dwCurrentState == SERVICE_START_PENDING) ||
     (dwCurrentState == SERVICE_STOP_PENDING))
    status_.dwControlsAccepted = 0;
  else 
    status_.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if((dwCurrentState == SERVICE_RUNNING) ||
     (dwCurrentState == SERVICE_STOPPED))
    status_.dwCheckPoint = 0;
  else
    status_.dwCheckPoint = dwCheckPoint++;

  SetServiceStatus(status_handle_, &status_);
}

void WinService::initPrivs(std::string const& username, std::string const& groupname)
{
// nothing here
}

void WinService::dropPrivs()
{
// nothing here
}

void WinService::chroot(std::string const& dir)
{
// nothing here
}

void WinService::daemonize()
{
// nothing here
}

bool WinService::isDaemonized()
{
  return true;
}

#endif
