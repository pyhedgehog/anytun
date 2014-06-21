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

#ifndef _RTPSESSION_H_
#define _RTPSESSION_H_

#include <boost/asio.hpp>

#include "../threadUtils.hpp"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

class RtpSession
{
public:
  typedef boost::asio::ip::udp proto;

  RtpSession(const std::string& call_id);

  bool isDead();
  bool isDead(bool d);

  bool isComplete();
  bool isComplete(bool c);

  proto::endpoint getLocalEnd1();
  RtpSession& setLocalEnd1(proto::endpoint e);
  proto::endpoint getLocalEnd2();
  RtpSession& setLocalEnd2(proto::endpoint e);

  proto::endpoint getRemoteEnd1();
  RtpSession& setRemoteEnd1(proto::endpoint e);
  proto::endpoint getRemoteEnd2();
  RtpSession& setRemoteEnd2(proto::endpoint e);

  RtpSession& setSeen1();
  bool getSeen1();

  RtpSession& setSeen2();
  bool getSeen2();

private:
  RtpSession(const RtpSession& src);

  void reinit();

  //TODO: check if this is ok
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    Lock lock(mutex_);

    // address of local_end1 and local_end2 are always equal
    std::string local_addr(local_end1_.address().to_string());
    uint16_t local_port1 = local_end1_.port();
    uint16_t local_port2 = local_end2_.port();

    std::string remote_addr1(remote_end1_.address().to_string());
    uint16_t remote_port1 = remote_end1_.port();
    std::string remote_addr2(remote_end2_.address().to_string());
    uint16_t remote_port2 = remote_end2_.port();

    ar& dead_;
    ar& complete_;
    ar& local_addr;
    ar& local_port1;
    ar& local_port2;
    ar& remote_addr1;
    ar& remote_port1;
    ar& remote_addr2;
    ar& remote_port2;
    ar& seen1_;
    ar& seen2_;

    proto::endpoint local_end1(boost::asio::ip::address::from_string(local_addr), local_port1);
    local_end1_ = local_end1;
    proto::endpoint local_end2(boost::asio::ip::address::from_string(local_addr), local_port2);
    local_end2_ = local_end2;

    proto::endpoint remote_end1(boost::asio::ip::address::from_string(remote_addr1), remote_port1);
    remote_end1_ = remote_end1;
    proto::endpoint remote_end2(boost::asio::ip::address::from_string(remote_addr2), remote_port2);
    remote_end2_ = remote_end2;

    if(complete_ && !dead_) {
      reinit();
    }

    in_sync_ = true;
  }

  bool in_sync_;
  ::Mutex mutex_;

  const std::string& call_id_;
  bool dead_;
  bool complete_;
  proto::endpoint local_end1_, local_end2_;
  proto::endpoint remote_end1_, remote_end2_;
  bool seen1_,seen2_; //has at least 1 packet been recieved?
};


#endif
