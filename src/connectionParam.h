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

#ifndef _CONNECTIONPARAM_H_
#define _CONNECTIONPARAM_H_

#include "keyDerivation.h"
#include "cipher.h"
#include "authAlgo.h"
#include "seqWindow.h"
#include "threadUtils.hpp"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

class ConnectionParam
{
public:
	ConnectionParam(const ConnectionParam & src);
	ConnectionParam( KeyDerivation& kd, SeqWindow& seq_window, seq_nr_t seq_nr_, boost::asio::ip::udp::endpoint endpoint);

  KeyDerivation& kd_;
  SeqWindow& seq_window_;
	seq_nr_t seq_nr_;
	boost::asio::ip::udp::endpoint endpoint_;

private:
  //TODO: check if this is ok
	Mutex mutex_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
	{
		Lock lock(mutex_);
		ar & kd_;
    ar & seq_window_;
    ar & seq_nr_;
    ar & remote_host_;
    ar & remote_port_;
	}
};

#endif
