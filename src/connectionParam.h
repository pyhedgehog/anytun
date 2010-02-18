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
#ifndef ANYTUN_connectionParam_h_INCLUDED
#define ANYTUN_connectionParam_h_INCLUDED

#include "keyDerivation.h"
#include "seqWindow.h"
#include "threadUtils.hpp"
#include "packetSource.h"
#include "log.h"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

class ConnectionParam
{
public:
  ConnectionParam(const ConnectionParam& src);
  ConnectionParam(KeyDerivation& kd, SeqWindow& seq_window, seq_nr_t seq_nr_, PacketSourceEndpoint remote_end);

  KeyDerivation& kd_;
  SeqWindow& seq_window_;
  seq_nr_t seq_nr_;
  PacketSourceEndpoint remote_end_;

private:
  //TODO: check if this is ok
  Mutex mutex_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    Lock lock(mutex_);
    std::string remote_host(remote_end_.address().to_string());
    uint16_t remote_port = remote_end_.port();
    ar& kd_;
    ar& seq_window_;
    ar& seq_nr_;
    ar& remote_host;
    ar& remote_port;
    PacketSourceEndpoint emptyEndpoint;
    UDPPacketSource::proto::endpoint endpoint(boost::asio::ip::address::from_string(remote_host), remote_port);
    //This is a workarround, against race condition in sync process
    //TODO: find a better solution
    if(endpoint != emptyEndpoint && remote_host != "::" && remote_host != "[::]" && remote_host != "0.0.0.0") {
      remote_end_ = endpoint;
    }
  }
};

#endif
