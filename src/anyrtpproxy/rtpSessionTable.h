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

#ifndef _RTPSESSIONTABLE_H
#define _RTPSESSIONTABLE_H

#include <map>

#include "../threadUtils.hpp"
#include "../datatypes.h"
#include "rtpSession.h"
typedef std::map<std::string,RtpSession*> RtpSessionMap;

class RtpSessionTable
{
public:
  static RtpSessionTable& instance();
  RtpSessionTable();
  ~RtpSessionTable();
  void delSession(const std::string& call_id);
  bool empty();
  void clear();
  ::Mutex& getMutex();
  RtpSessionMap::iterator getBeginUnlocked();
  RtpSessionMap::iterator getEndUnlocked();
  RtpSession& getOrNewSession(const std::string& call_id, bool& isnew);
  RtpSession& getOrNewSessionUnlocked(const std::string& call_id, bool& isnew);
  RtpSession& getSession(const std::string& call_id);

private:
  static ::Mutex instMutex;
  static RtpSessionTable* inst;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(RtpSessionTable::inst != 0) {
        delete RtpSessionTable::inst;
      }
    }
  };
  RtpSessionTable(const RtpSessionTable& s);
  void operator=(const RtpSessionTable& s);
  RtpSessionMap map_;
  ::Mutex mutex_;
};

extern RtpSessionTable& gRtpSessionTable;

#endif
