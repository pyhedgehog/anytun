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

#include <iostream>
#include <string>
#include <syslog.h>

#include "log.h"

#include "threadUtils.hpp"

Log* Log::inst = NULL;
Mutex Log::instMutex;
Log& cLog = Log::instance();

LogStringBuilder::LogStringBuilder(LogStringBuilder const& src) : log(src.log), prio(src.prio) 
{
  stream << src.stream.str();
}

LogStringBuilder::LogStringBuilder(Log& l, int p) : log(l), prio(p) 
{
      // do something on the start of the line.
}

LogStringBuilder::~LogStringBuilder() 
{
  Lock lock(log.mutex);
  syslog(prio | log.getFacility(), stream.str().c_str());  
}

Log& Log::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new Log();
  
  return *inst;
}

Log::Log()
{
  facility = LOG_DAEMON;
  logName = "anytun";
  open();
}

Log::~Log()
{
  closelog();
}

void Log::open()
{
  openlog(logName.c_str(), LOG_PID, facility);
}

Log& Log::setLogName(std::string newLogName)
{
  logName = newLogName;
  open();
  return *this;
}

Log& Log::setFacility(int newFacility)
{
  facility = newFacility;
  open();
  return *this;
}
