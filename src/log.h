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

#ifndef ANYTUN_log_h_INCLUDED
#define ANYTUN_log_h_INCLUDED

#include <string>
#include <sstream>

#include "logTargets.h"
#include "threadUtils.hpp"

class Log;

class LogStringBuilder
{
public:
  LogStringBuilder(LogStringBuilder const& src);
  LogStringBuilder(Log& l, int p);
  ~LogStringBuilder();

  template<class T>
  std::ostream& operator<<(T const& value) { return stream << value; }

private:
  Log& log;
  int prio;
  std::stringstream stream;
};

class Log
{
public:
  static const int PRIO_ERROR = 1;
  static const int PRIO_WARNING = 2;
  static const int PRIO_NOTICE = 3;
  static const int PRIO_INFO = 4;
  static const int PRIO_DEBUG = 5;

  static std::string prioToString(int prio);

  static Log& instance();

  void addTarget(std::string conf);
  void addTarget(LogTargetList::target_type_t type, int prio, std::string conf);
  LogStringBuilder msg(int prio=PRIO_INFO) { return LogStringBuilder(*this, prio); }

private:
  Log() {};
  ~Log() {};
  Log(const Log& l);
  void operator=(const Log& l);

  static Log* inst;
  static Mutex instMutex;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(Log::inst != 0) {
        delete Log::inst;
      }
    }
  };
  friend class instanceCleaner;

  void log(std::string msg, int prio);

  Mutex mutex;
  friend class LogStringBuilder;

  LogTargetList targets;
};

extern Log& cLog;

#endif
