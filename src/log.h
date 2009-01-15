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
#ifndef NOSYSLOG
#include <syslog.h>
#endif

#include "threadUtils.hpp"


#define STERROR_TEXT_MAX 100

#ifndef NOCRYPT
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
  LogErrno(int e) : err_(e) {};
  int err_;
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

class Log : public std::ostringstream
{
public:
#ifndef NOSYSLOG
  static const int FAC_USER = LOG_USER;
  static const int FAC_MAIL = LOG_MAIL;
  static const int FAC_DAEMON = LOG_DAEMON;
  static const int FAC_AUTH = LOG_AUTH;
  static const int FAC_SYSLOG = LOG_SYSLOG;
  static const int FAC_LPR = LOG_LPR;
  static const int FAC_NEWS = LOG_NEWS;
  static const int FAC_UUCP = LOG_UUCP;
  static const int FAC_CRON = LOG_CRON;
  static const int FAC_AUTHPRIV = LOG_AUTHPRIV;
  static const int FAC_FTP = LOG_FTP;
  static const int FAC_LOCAL0 = LOG_LOCAL0;
  static const int FAC_LOCAL1 = LOG_LOCAL1;
  static const int FAC_LOCAL2 = LOG_LOCAL2;
  static const int FAC_LOCAL3 = LOG_LOCAL3;
  static const int FAC_LOCAL4 = LOG_LOCAL4;
  static const int FAC_LOCAL5 = LOG_LOCAL5;
  static const int FAC_LOCAL6 = LOG_LOCAL6;
  static const int FAC_LOCAL7 = LOG_LOCAL7;

  static const int PRIO_EMERG = LOG_EMERG;
  static const int PRIO_ALERT = LOG_ALERT;
  static const int PRIO_CRIT = LOG_CRIT;
  static const int PRIO_ERR = LOG_ERR;
  static const int PRIO_WARNING = LOG_WARNING;
  static const int PRIO_NOTICE = LOG_NOTICE;
  static const int PRIO_INFO = LOG_INFO;
  static const int PRIO_DEBUG = LOG_DEBUG;
#else
  static const int FAC_USER = 0;
  static const int FAC_MAIL = 0;
  static const int FAC_DAEMON = 0;
  static const int FAC_AUTH = 0;
  static const int FAC_SYSLOG = 0;
  static const int FAC_LPR = 0;
  static const int FAC_NEWS = 0;
  static const int FAC_UUCP = 0;
  static const int FAC_CRON = 0;
  static const int FAC_AUTHPRIV = 0;
  static const int FAC_FTP = 0;
  static const int FAC_LOCAL0 = 0;
  static const int FAC_LOCAL1 = 0;
  static const int FAC_LOCAL2 = 0;
  static const int FAC_LOCAL3 = 0;
  static const int FAC_LOCAL4 = 0;
  static const int FAC_LOCAL5 = 0;
  static const int FAC_LOCAL6 = 0;
  static const int FAC_LOCAL7 = 0;

  static const int PRIO_EMERG = 0;
  static const int PRIO_ALERT = 0;
  static const int PRIO_CRIT = 0;
  static const int PRIO_ERR = 0;
  static const int PRIO_WARNING = 0;
  static const int PRIO_NOTICE = 0;
  static const int PRIO_INFO = 0;
  static const int PRIO_DEBUG = 0;
#endif

  static Log& instance();

  Log& setLogName(std::string newLogName); 
  std::string getLogName() const { return logName; }
  Log& setFacility(int newFacility);
  int getFacility() const { return facility; }

  LogStringBuilder msg(int prio=PRIO_INFO) { return LogStringBuilder(*this, prio); }

private:
  Log();
  ~Log();
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

  void open();

  Mutex mutex;
  friend class LogStringBuilder;

  std::string logName;
  int facility;
};

extern Log& cLog;

#endif
