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

#ifdef WIN_SERVICE

#include <iostream>

#include <windows.h>

#include "winService.h"
#include "../log.h"
#include "../threadUtils.hpp"

WinService* WinService::inst = NULL;
Mutex WinService::instMutex;
WinService& gWinService = WinService::instance();

WinService& WinService::instance()
{
	Lock lock(instMutex);
	static instanceCleaner c;
	if(!inst)
		inst = new WinService();
	
	return *inst;
}

WinService::~WinService()
{
  if(started_)
    CloseHandle(stop_event_);
}

void WinService::install()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  char szPath[MAX_PATH];

  if(!GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
    std::stringstream msg;  
    msg << "Error on GetModuleFileName: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
  }

  schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if(NULL == schSCManager) {
    std::stringstream msg;  
    msg << "Error on OpenSCManager: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
  }

  schService = CreateServiceA(schSCManager, SVC_NAME, SVC_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, 
                              SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
  if(schService == NULL) {
    CloseServiceHandle(schSCManager);
    std::stringstream msg;  
    msg << "Error on CreateService: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
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
  if(NULL == schSCManager) {
    std::stringstream msg;  
    msg << "Error on OpenSCManager: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
  }

  schService = OpenServiceA(schSCManager, SVC_NAME, SERVICE_ALL_ACCESS);
  if(schService == NULL) {
    CloseServiceHandle(schSCManager);
    std::stringstream msg;  
    msg << "Error on CreateService: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
  }

  if(!DeleteService(schService)) {
    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
    std::stringstream msg;  
    msg << "Error on DeleteService: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
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

  if(!StartServiceCtrlDispatcherA(DispatchTable)) {
    std::stringstream msg;  
    msg << "Error on StartServiceCtrlDispatcher: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
  }    
}

void WinService::waitForStop()
{
  if(!started_)
    throw std::runtime_error("Service not started correctly");

  WaitForSingleObject(stop_event_, INFINITE);
  reportStatus(SERVICE_STOP_PENDING, NO_ERROR);
}

void WinService::stop()
{
  if(!started_)
    throw std::runtime_error("Service not started correctly");

  reportStatus(SERVICE_STOPPED, NO_ERROR);
}

int real_main(int argc, char* argv[]);

VOID WINAPI WinService::main(DWORD dwArgc, LPTSTR *lpszArgv)
{
  if(gWinService.started_) {
    cLog.msg(Log::PRIO_ERR) << "Service is already running";
    return;
  }

  gWinService.status_handle_ = RegisterServiceCtrlHandlerA(SVC_NAME, WinService::ctrlHandler);
  if(!gWinService.status_handle_) { 
    cLog.msg(Log::PRIO_ERR) << "Error on RegisterServiceCtrlHandler: " << LogErrno(GetLastError());
    return;
  }
  gWinService.status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
  gWinService.status_.dwServiceSpecificExitCode = 0;    
  gWinService.reportStatus(SERVICE_START_PENDING, NO_ERROR);

  gWinService.stop_event_ = CreateEvent(NULL, true, false, NULL);
  if(!gWinService.stop_event_) {
    cLog.msg(Log::PRIO_ERR) << "Error on CreateEvent: " << LogErrno(GetLastError());
    gWinService.reportStatus(SERVICE_STOPPED, -1);
    return;
  }
  gWinService.started_ = true;
  gWinService.reportStatus(SERVICE_RUNNING, NO_ERROR);
  
  real_main(dwArgc, lpszArgv);
}

VOID WINAPI WinService::ctrlHandler(DWORD dwCtrl)
{
  switch(dwCtrl) {
    case SERVICE_CONTROL_STOP: {
      gWinService.reportStatus(SERVICE_STOP_PENDING, NO_ERROR);
      SetEvent(gWinService.stop_event_);
      return;
    }
    case SERVICE_CONTROL_INTERROGATE: break;
    default: break;
  }
  gWinService.reportStatus(gWinService.status_.dwCurrentState, NO_ERROR);
}

void WinService::reportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;

  status_.dwCurrentState = dwCurrentState;
  status_.dwWin32ExitCode = dwWin32ExitCode;
  status_.dwWaitHint = dwWaitHint;

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

#endif