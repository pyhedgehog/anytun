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

#include "rtpSession.h"

#include "callIdQueue.h"

RtpSession::RtpSession(const std::string& call_id) : in_sync_(false), call_id_(call_id) , dead_(false), complete_(false), 
                                                     seen1_(false), seen2_(false)
{  
}

void RtpSession::reinit()
{
  gCallIdQueue.push(call_id_);
}

bool RtpSession::isDead()
{
  Lock lock(mutex_);
  return (dead_ && in_sync_);
}

bool RtpSession::isDead(bool d)
{
  Lock Lock(mutex_);
  return dead_ = d;
}

bool RtpSession::isComplete()
{
  Lock lock(mutex_);
  return complete_;
}

bool RtpSession::isComplete(bool c)
{
  Lock lock(mutex_);
  return complete_ = c;
}

bool RtpSession::getSeen1()
{
  Lock lock(mutex_);
  return seen1_;
}

RtpSession& RtpSession::setSeen1()
{
  Lock lock(mutex_);
  //in_sync_ = false;
  seen1_ = true;
  return *this;
}

bool RtpSession::getSeen2()
{
  Lock lock(mutex_);
  return seen2_;
}

RtpSession& RtpSession::setSeen2()
{
  Lock lock(mutex_);
  //in_sync_ = false;
  seen2_ = true;
  return *this;
}

RtpSession::proto::endpoint RtpSession::getLocalEnd1()
{
  Lock lock(mutex_);
  return local_end1_;
}

RtpSession& RtpSession::setLocalEnd1(RtpSession::proto::endpoint e)
{
  Lock lock(mutex_);
  in_sync_ = false;
  local_end1_ = e;
  return *this;
}

RtpSession::proto::endpoint RtpSession::getLocalEnd2()
{
  Lock lock(mutex_);
  return local_end2_;
}

RtpSession& RtpSession::setLocalEnd2(RtpSession::proto::endpoint e)
{
  Lock lock(mutex_);
  in_sync_ = false;
  local_end2_ = e;
  return *this;
}

RtpSession::proto::endpoint RtpSession::getRemoteEnd1()
{
  Lock lock(mutex_);
  return remote_end1_;
}

RtpSession& RtpSession::setRemoteEnd1(RtpSession::proto::endpoint e)
{
  Lock lock(mutex_);
  in_sync_ = false;
  remote_end1_ = e;
  return *this;
}

RtpSession::proto::endpoint RtpSession::getRemoteEnd2()
{
  Lock lock(mutex_);
  return remote_end2_;
}

RtpSession& RtpSession::setRemoteEnd2(RtpSession::proto::endpoint e)
{
  Lock lock(mutex_);
  in_sync_ = false;
  remote_end2_ = e;
  return *this;
}


