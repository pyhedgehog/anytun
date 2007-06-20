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
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <string>
#include <sstream>
#include <syslog.h>

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

class Log : public std::ostringstream
{
public:
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
