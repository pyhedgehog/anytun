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

#ifndef ANYTUN_sysExec_h_INCLUDED
#define ANYTUN_sysExec_h_INCLUDED

#include <vector>
#include <list>
#include <string>

typedef std::vector<std::string> StringVector;
typedef std::list<std::string> StringList;

class SysExec
{
public:
  SysExec(std::string const& script);
  SysExec(std::string const& script, StringVector args);
  SysExec(std::string const& script, StringList env);
  SysExec(std::string const& script, StringVector args, StringList env);
  ~SysExec();

  int waitForScript();
  int getReturnCode() const;

  static void waitAndDestroy(SysExec*& s);

private:
  void doExec(StringVector args, StringList env);

  std::string script_;
  bool closed_;
#if !defined(_MSC_VER) && !defined(MINGW)
  pid_t pid_;
  int pipefd_;
  int return_code_;
#else
  PROCESS_INFORMATION process_info_;
  DWORD return_code_;
#endif


};

#endif
