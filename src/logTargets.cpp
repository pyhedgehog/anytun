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

#include <sstream>

#include "datatypes.h"

#include "logTargets.h"
#include "log.h"
#include "anytunError.h"

#include "options.h"

#ifdef LOG_WINEVENTLOG
#include <windows.h>
#include <strsafe.h>
#endif

LogTarget::LogTarget() : opened(false), enabled(false), max_prio(Log::PRIO_NOTICE)
{
}

LogTarget::LogTarget(int prio) : opened(false), enabled(false), max_prio(prio)
{
}

LogTargetList::~LogTargetList()
{
  clear();
}

LogTargetList::target_type_t LogTargetList::targetTypeFromString(std::string type)
{
  if(type == "syslog") return TARGET_SYSLOG;
  if(type == "file") return TARGET_FILE;
  if(type == "stdout") return TARGET_STDOUT;
  if(type == "stderr") return TARGET_STDERR;
  if(type == "eventlog") return TARGET_WINEVENTLOG;
  return TARGET_UNKNOWN;
}

std::string LogTargetList::targetTypeToString(target_type_t type)
{
  switch(type) {
  case TARGET_SYSLOG: return "syslog";
  case TARGET_FILE: return "file";
  case TARGET_STDOUT: return "stdout";
  case TARGET_STDERR: return "stderr";
  case TARGET_WINEVENTLOG: return "eventlog";
  default: return "unknown";
  }
}

LogTarget* LogTargetList::add(std::string conf)
{
  std::stringstream s(conf);
  std::string type;
  getline(s, type, ':');
  if(!s.good())
    throw syntax_error(conf, 0);

  int prio = Log::PRIO_NOTICE;
  s >> prio;
  if(s.fail())
    throw syntax_error(conf, conf.find_first_of(':')+1);

  char buff[100];
  if(s.good()) {
    s.get(buff[0]);
    if(buff[0] != ',')
      throw syntax_error(conf, (s.tellg() > 0) ? static_cast<size_t>(s.tellg()) - 1 : 0);
    s.get(buff, 100);
  }
  else
    buff[0] = 0;

  return add(targetTypeFromString(type), prio, buff);
}

LogTarget* LogTargetList::add(target_type_t type, int prio, std::string conf)
{
  switch(type) {
  case TARGET_SYSLOG: {
    #ifdef LOG_SYSLOG
    if(!LogTargetSyslog::duplicateAllowed() && targets.count(TARGET_SYSLOG))
      AnytunError::throwErr() << targetTypeToString(TARGET_SYSLOG) << " logtarget is supported only once";

    return targets.insert(TargetsMap::value_type(TARGET_SYSLOG, new LogTargetSyslog(prio, conf)))->second;
    #else
    AnytunError::throwErr() << targetTypeToString(TARGET_SYSLOG) << " logtarget is not supported";
    #endif
  }
  case TARGET_FILE: {
    #ifdef LOG_FILE
    if(!LogTargetFile::duplicateAllowed() && targets.count(TARGET_FILE))
      AnytunError::throwErr() << targetTypeToString(TARGET_FILE) << " logtarget is supported only once";

    return targets.insert(TargetsMap::value_type(TARGET_FILE, new LogTargetFile(prio, conf)))->second;
    #else
    AnytunError::throwErr() << targetTypeToString(TARGET_FILE) << " logtarget is not supported";
    #endif
  }
  case TARGET_STDOUT: 
  case TARGET_STDERR: {
    #ifdef LOG_STDOUT
    if(!LogTargetStdout::duplicateAllowed() && targets.count(type))
      AnytunError::throwErr() << targetTypeToString(type) << " logtarget is supported only once";
    
    if(type == TARGET_STDERR)
      return targets.insert(TargetsMap::value_type(type, new LogTargetStdout(prio, std::cerr)))->second;
    else
      return targets.insert(TargetsMap::value_type(type, new LogTargetStdout(prio, std::cout)))->second;
    #else
    AnytunError::throwErr() << targetTypeToString(type) + " logtarget is not supported";
    #endif
  }
  case TARGET_WINEVENTLOG: {
    #ifdef LOG_WINEVENTLOG
    if(!LogTargetWinEventlog::duplicateAllowed() && targets.count(TARGET_WINEVENTLOG))
      AnytunError::throwErr() << targetTypeToString(TARGET_WINEVENTLOG) << " logtarget is supported only once";

    return targets.insert(TargetsMap::value_type(TARGET_WINEVENTLOG, new LogTargetWinEventlog(prio, conf)))->second;
    #else
    AnytunError::throwErr() << targetTypeToString(TARGET_WINEVENTLOG) << " logtarget is not supported";
    #endif
  }
  default: 
    AnytunError::throwErr() << "unknown log target";
  }
  return NULL;
}

void LogTargetList::clear()
{
  TargetsMap::iterator it;
  for(it = targets.begin(); it != targets.end(); ++it)
    delete it->second;
  targets.clear();
}
  
void LogTargetList::log(std::string msg, int prio)
{
  TargetsMap::const_iterator it;
  for(it = targets.begin(); it != targets.end(); ++it) {
    if(it->second->isEnabled() && it->second->getMaxPrio() >= prio)
      it->second->log(msg, prio);
  }
}


#ifdef LOG_SYSLOG
int LogTargetSyslog::facilityFromString(std::string fac)
{
  if(fac == "user") return FAC_USER;
  if(fac == "mail") return FAC_MAIL;
  if(fac == "daemon") return FAC_DAEMON;
  if(fac == "auth") return FAC_AUTH;
  if(fac == "syslog") return FAC_SYSLOG;
  if(fac == "lpr") return FAC_LPR;
  if(fac == "news") return FAC_NEWS;
  if(fac == "uucp") return FAC_UUCP;
  if(fac == "cron") return FAC_CRON;
  if(fac == "authpriv") return FAC_AUTHPRIV;
  if(fac == "ftp") return FAC_FTP;
  if(fac == "local0") return FAC_LOCAL0;
  if(fac == "local1") return FAC_LOCAL1;
  if(fac == "local2") return FAC_LOCAL2;
  if(fac == "local3") return FAC_LOCAL3;
  if(fac == "local4") return FAC_LOCAL4;
  if(fac == "local5") return FAC_LOCAL5;
  if(fac == "local6") return FAC_LOCAL6;
  if(fac == "local7") return FAC_LOCAL7;
  
  AnytunError::throwErr() << "unknown syslog facility";
  return 0;
}

std::string LogTargetSyslog::facilityToString(int fac)
{
  switch(fac) {
  case FAC_USER: return "user";
  case FAC_MAIL: return "mail";
  case FAC_DAEMON: return "daemon";
  case FAC_AUTH: return "auth";
  case FAC_SYSLOG: return "syslog";
  case FAC_LPR: return "lpr";
  case FAC_NEWS: return "news";
  case FAC_UUCP: return "uucp";
  case FAC_CRON: return "cron";
  case FAC_AUTHPRIV: return "authpriv";
  case FAC_FTP: return "ftp";
  case FAC_LOCAL0: return "local0";
  case FAC_LOCAL1: return "local1";
  case FAC_LOCAL2: return "local2";
  case FAC_LOCAL3: return "local3";
  case FAC_LOCAL4: return "local4";
  case FAC_LOCAL5: return "local5";
  case FAC_LOCAL6: return "local6";
  case FAC_LOCAL7: return "local7";
  default: AnytunError::throwErr() << "unknown syslog facility";
  }
  return "";
}

LogTargetSyslog::LogTargetSyslog(int prio, std::string conf) : LogTarget(prio)
{
  std::stringstream s(conf);
  facility = FAC_DAEMON;
  getline(s, logname, ',');
  if(s.fail()) {
    logname = "anytun";
    return;
  }
  std::string fac;
  getline(s, fac, ',');
  if(s.fail())
    return;

  facility = LogTargetSyslog::facilityFromString(fac);
}

LogTargetSyslog::~LogTargetSyslog()
{
  if(opened)
    close();
}

void LogTargetSyslog::open()
{
  openlog(logname.c_str(), LOG_PID, facility);
  opened = true;
}

void LogTargetSyslog::close()
{
  closelog();
  opened = false;
}

void LogTargetSyslog::log(std::string msg, int prio)
{
  if(!opened)
    return;

  syslog((prio + 2) | facility, "%s", msg.c_str());  
}

LogTargetSyslog& LogTargetSyslog::setLogName(std::string l)
{
  logname = l;
  if(opened)
    close();
  open();
  return *this;
}

LogTargetSyslog& LogTargetSyslog::setFacility(int f)
{
  facility = f;
  if(opened)
    close();
  open();
  return *this;
}
#endif


#ifdef LOG_FILE
LogTargetFile::LogTargetFile(int prio, std::string conf) : LogTarget(prio)
{
  std::stringstream s(conf);
  getline(s, logfilename, ',');
  if(s.fail())
    logfilename = "anytun.log";
}

LogTargetFile::~LogTargetFile()
{
  if(opened)
    close();
}

void LogTargetFile::open()
{
  logfile.open(logfilename.c_str(), std::fstream::out | std::fstream::app);
  opened = logfile.is_open();
}

void LogTargetFile::close()
{
  if(logfile.is_open())
    logfile.close();
  opened = false;
}

void LogTargetFile::log(std::string msg, int prio)
{
  if(!opened)
    return;

  logfile << Log::prioToString(prio) << ": " << msg << std::endl;
}

LogTargetFile& LogTargetFile::setLogFilename(std::string l)
{
  logfilename = l;
  if(opened)
    close();
  open();
  return *this;
}
#endif


#ifdef LOG_STDOUT
LogTargetStdout::LogTargetStdout(int prio, std::ostream& s) : LogTarget(prio), stream(s)
{
}

LogTargetStdout::~LogTargetStdout()
{
  if(opened)
    close();
}

void LogTargetStdout::open()
{
  opened = true;
}

void LogTargetStdout::close()
{
  opened = false;
}

void LogTargetStdout::log(std::string msg, int prio)
{
  if(!opened)
    return;

  stream << "LOG-" << Log::prioToString(prio) << ": " << msg << std::endl;
}
#endif


#ifdef LOG_WINEVENTLOG
LogTargetWinEventlog::LogTargetWinEventlog(int prio, std::string conf) : LogTarget(prio)
{
  std::stringstream s(conf);
  getline(s, logname, ',');
  if(s.fail())
    logname = "anytun";
}

LogTargetWinEventlog::~LogTargetWinEventlog()
{
  if(opened)
    close();
}

void LogTargetWinEventlog::open()
{
  h_event_source = RegisterEventSourceA(NULL, logname.c_str());
  if(h_event_source)
    opened = true;
}

void LogTargetWinEventlog::close()
{
  if(h_event_source)
    DeregisterEventSource(h_event_source);
  opened = false;
}

void LogTargetWinEventlog::log(std::string msg, int prio)
{
  if(!opened)
    return;

  LPCTSTR lpszStrings[1];  
  CHAR buffer[STERROR_TEXT_MAX];
  StringCchPrintfA(buffer, STERROR_TEXT_MAX, "%s", msg.c_str());
  lpszStrings[0] = buffer;
  if(h_event_source)
    ReportEventA(h_event_source, prioToEventLogType(prio), 0, prio, NULL, 1, 0, lpszStrings, NULL);
}

LogTargetWinEventlog& LogTargetWinEventlog::setLogName(std::string l)
{
  logname = l;
  if(opened)
    close();
  open();
  return *this;
}

WORD LogTargetWinEventlog::prioToEventLogType(int prio)
{
  switch(prio) {
  case Log::PRIO_ERROR: return EVENTLOG_ERROR_TYPE;
  case Log::PRIO_WARNING: return EVENTLOG_WARNING_TYPE;
  case Log::PRIO_NOTICE: return EVENTLOG_INFORMATION_TYPE;
  case Log::PRIO_INFO: return EVENTLOG_SUCCESS;
  case Log::PRIO_DEBUG: return EVENTLOG_INFORMATION_TYPE;
  default: return EVENTLOG_ERROR_TYPE;
  }
}
#endif
