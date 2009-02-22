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

#ifndef _LOG_H_
#define _LOG_H_

#include <string>
#include <sstream>

#include "logTargets.h"

#ifdef LOG_SYSLOG
#include <syslog.h>
#endif

#include "threadUtils.hpp"

#define STERROR_TEXT_MAX 200

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>

class LogGpgError
{
public:
  LogGpgError(gcry_error_t e) : err_(e) {};
  gcry_error_t err_;
};
std::ostream& operator<<(std::ostream& stream, LogGpgError const& value);
#endif
#endif

class LogErrno
{
public:
  LogErrno(system_error_t e) : err_(e) {};
  system_error_t err_;
};
std::ostream& operator<<(std::ostream& stream, LogErrno const& value);

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
#ifdef LOG_SYSLOG
  static const int PRIO_EMERG = LOG_EMERG;
  static const int PRIO_ALERT = LOG_ALERT;
  static const int PRIO_CRIT = LOG_CRIT;
  static const int PRIO_ERR = LOG_ERR;
  static const int PRIO_WARNING = LOG_WARNING;
  static const int PRIO_NOTICE = LOG_NOTICE;
  static const int PRIO_INFO = LOG_INFO;
  static const int PRIO_DEBUG = LOG_DEBUG;
#else
  static const int PRIO_EMERG = 0;
  static const int PRIO_ALERT = 1;
  static const int PRIO_CRIT = 2;
  static const int PRIO_ERR = 3;
  static const int PRIO_WARNING = 4;
  static const int PRIO_NOTICE = 5;
  static const int PRIO_INFO = 6;
  static const int PRIO_DEBUG = 7;
#endif
  static std::string prioToString(int prio);

  static Log& instance();

  void addTarget(std::string conf);
  void addTarget(LogTargetList::target_type_t type, int prio, std::string conf);
  LogStringBuilder msg(int prio=PRIO_INFO) { return LogStringBuilder(*this, prio); }

private:
  Log() {};
  ~Log() {};
  Log(const Log &l);
  void operator=(const Log &l);

  static Log* inst;
  static Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(Log::inst != 0)
        delete Log::inst;
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
