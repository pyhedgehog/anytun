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

#ifndef ANYTUN_logTargets_h_INCLUDED
#define ANYTUN_logTargets_h_INCLUDED

#include <string>
#include <map>

#ifdef LOG_SYSLOG
#include <syslog.h>
#endif

#ifdef LOG_FILE
#include <fstream>
#endif

#include "datatypes.h"

class LogTarget
{
public:
  LogTarget();
  LogTarget(int prio);
  virtual ~LogTarget() {};

  virtual void open() = 0;
  virtual void close() = 0;
  bool isOpen() { return opened; };

  void enable() { enabled = true; };
  void disable() { enabled = false; };
  bool isEnabled() { return enabled; };

  int getMaxPrio() { return max_prio; };
  void setMaxPrio(int p) { max_prio = p; };

  virtual void log(std::string msg, int prio) = 0;

protected:
  bool opened;
  bool enabled;
  int max_prio;
};

class LogTargetList
{
public:
  typedef enum { TARGET_UNKNOWN, TARGET_SYSLOG, TARGET_FILE,
                 TARGET_STDOUT, TARGET_STDERR, TARGET_WINEVENTLOG
               } target_type_t;

  static target_type_t targetTypeFromString(std::string type);
  static std::string targetTypeToString(target_type_t type);

  ~LogTargetList();
  LogTarget* add(std::string conf);
  LogTarget* add(target_type_t type, int prio, std::string conf);
  void clear();

  void log(std::string msg, int prio);

private:
  typedef std::multimap<target_type_t, LogTarget*> TargetsMap;
  TargetsMap targets;
};


#ifdef LOG_SYSLOG
class LogTargetSyslog : public LogTarget
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

  static int facilityFromString(std::string fac);
  static std::string facilityToString(int fac);

  LogTargetSyslog(int prio, std::string conf);
  ~LogTargetSyslog();

  void open();
  void close();
  void log(std::string msg, int prio);
  static bool duplicateAllowed() { return false; };

  LogTargetSyslog& setLogName(std::string l);
  std::string getLogName() const { return logname; }
  LogTargetSyslog& setFacility(int f);
  int getFacility() const { return facility; }

private:
  std::string logname;
  int facility;
};
#endif

#ifdef LOG_FILE
class LogTargetFile : public LogTarget
{
public:
  LogTargetFile(int prio, std::string conf);
  ~LogTargetFile();

  void open();
  void close();
  void log(std::string msg, int prio);
  static bool duplicateAllowed() { return true; };

  LogTargetFile& setLogFilename(std::string l);
  std::string getLogFilename() const { return logfilename; }

private:
  std::string logfilename;
  std::ofstream logfile;
};
#endif

#ifdef LOG_STDOUT
class LogTargetStdout : public LogTarget
{
public:
  LogTargetStdout(int prio, std::ostream& s);
  ~LogTargetStdout();

  void open();
  void close();
  void log(std::string msg, int prio);
  static bool duplicateAllowed() { return false; };

private:
  std::ostream& stream;
};
#endif

#ifdef LOG_WINEVENTLOG
class LogTargetWinEventlog : public LogTarget
{
public:
  static WORD prioToEventLogType(int prio);

  LogTargetWinEventlog(int prio, std::string conf);
  ~LogTargetWinEventlog();

  void open();
  void close();
  void log(std::string msg, int prio);
  static bool duplicateAllowed() { return false; };

  LogTargetWinEventlog& setLogName(std::string l);
  std::string getLogName() const { return logname; };

private:
  std::string logname;
  HANDLE h_event_source;
};
#endif

#endif
