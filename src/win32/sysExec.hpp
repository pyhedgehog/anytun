/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#pragma once
#ifndef ANYTUN_sysexec_hpp_INCLUDED
#define ANYTUN_sysexec_hpp_INCLUDED

#include <algorithm>
#include <iostream> // todo remove
#include <windows.h>

SysExec::~SysExec()
{
  if(!closed_) {
    CloseHandle(process_info_.hProcess);
    CloseHandle(process_info_.hThread);
  }
}

STARTUPINFOA getStartupInfo()
{
  STARTUPINFOA startup_info;
  startup_info.cb = sizeof(STARTUPINFOA);
  GetStartupInfoA(&startup_info);

  //startup_info.dwFlags = STARTF_USESTDHANDLES;
  //startup_info.hStdInput = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0, 0, 0); // INVALID_HANDLE_VALUE;
  //startup_info.hStdOutput = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0, 0, 0); // INVALID_HANDLE_VALUE;
  //startup_info.hStdError = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0, 0, 0); // INVALID_HANDLE_VALUE;
  startup_info.dwFlags |= STARTF_USESHOWWINDOW;
  startup_info.wShowWindow = SW_HIDE;

  return startup_info;
}

char const* const BATCH_FILE_EXTS[] = { ".bat", ".cmd" };
int const BATCH_FILE_EXTS_COUNT = sizeof(BATCH_FILE_EXTS) / sizeof(BATCH_FILE_EXTS[0]);

bool endsWith(std::string const& string, std::string const& suffix)
{
  return string.find(suffix, string.size() - suffix.size()) != std::string::npos;
}

void SysExec::doExec(StringVector args, StringList env_param)
{
  std::vector<char> arguments;

  bool isBatchFile = false;
  for(int i = 0; i < BATCH_FILE_EXTS_COUNT; ++i) {
    if(endsWith(script_, BATCH_FILE_EXTS[i])) {
      isBatchFile = true;
      break;
    }
  }

  if(isBatchFile) {
    std::string const BATCH_INTERPRETER = "cmd /c \"";
    arguments.insert(arguments.end(), BATCH_INTERPRETER.begin(), BATCH_INTERPRETER.end());
  }
  arguments.push_back('\"');
  arguments.insert(arguments.end(), script_.begin(), script_.end());
  arguments.push_back('\"');
  arguments.push_back(' ');

  for(StringVector::const_iterator it = args.begin(); it != args.end(); ++it) {
    arguments.push_back('\"');
    arguments.insert(arguments.end(), it->begin(), it->end());
    arguments.push_back('\"');
    arguments.push_back(' ');
  }

  if(isBatchFile) {
    arguments.push_back('\"');
  }
  arguments.push_back(0);

  STARTUPINFOA startup_info = getStartupInfo();

  std::map<std::string, std::string> envDict;
  for(StringList::const_iterator it = env_param.begin(); it != env_param.begin(); ++it) {
    size_t delimiter_pos = it->find('=');
    envDict.insert(std::make_pair(it->substr(0, delimiter_pos), it->substr(delimiter_pos + 1)));
  }
  std::vector<char> env;
  for(std::map<std::string, std::string>::iterator it = envDict.begin(); it != envDict.end(); ++it) {
    env.insert(env.end(), it->first.begin(), it->first.end());
    env.push_back(0);
  }
  env.push_back(0);

  if(!CreateProcessA(NULL,
                     &arguments[0],
                     NULL,
                     NULL,
                     false,
                     0,
                     &env[0],
                     NULL,
                     &startup_info,
                     &process_info_
                    )) {
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script_ << "' CreateProcess() error: " << GetLastError();
    return;
  }
}

int SysExec::waitForScript()
{
  DWORD result = WaitForSingleObject(process_info_.hProcess, INFINITE);
  assert(WAIT_OBJECT_0 == result); // WAIT_FAILED, WAIT_TIMEOUT ... ???
  bool success = GetExitCodeProcess(process_info_.hProcess, &return_code_) != 0;
  assert(true == success); // false -> HU?

  CloseHandle(process_info_.hProcess);
  CloseHandle(process_info_.hThread);
  closed_ = true;

  return static_cast<int>(return_code_);
}

void SysExec::waitAndDestroy(SysExec*& s)
{
  if(!s) {
    return;
  }

  s->waitForScript();
  cLog.msg(Log::PRIO_NOTICE) << "script '" << s->script_ << "' returned " << s->return_code_;

  delete(s);
  s = NULL;
}

#endif // ANYTUN_sysexec_hpp_INCLUDED
