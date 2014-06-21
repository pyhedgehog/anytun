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

#include <iostream>
#include <string>
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
  log.log(stream.str(), prio);
}

Log& Log::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst) {
    inst = new Log();
  }

  return *inst;
}

void Log::addTarget(std::string conf)
{
  Lock lock(mutex);
  LogTarget* target = targets.add(conf);
  target->open();
  if(target->getMaxPrio() > 0) {
    target->enable();
  }
}

void Log::addTarget(LogTargetList::target_type_t type, int prio, std::string conf)
{
  Lock lock(mutex);
  LogTarget* target = targets.add(type, prio, conf);
  target->open();
  if(target->getMaxPrio() > 0) {
    target->enable();
  }
}

void Log::log(std::string msg, int prio)
{
  Lock lock(mutex);
  targets.log(msg, prio);
}

std::string Log::prioToString(int prio)
{
  switch(prio) {
  case PRIO_ERROR:
    return "ERROR";
  case PRIO_WARNING:
    return "WARNING";
  case PRIO_NOTICE:
    return "NOTICE";
  case PRIO_INFO:
    return "INFO";
  case PRIO_DEBUG:
    return "DEBUG";
  default:
    return "UNKNOWN";
  }
}
