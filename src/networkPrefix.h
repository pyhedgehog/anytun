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

#ifndef _NETWORK_PREFIX_H
#define _NETWORK_PREFIX_H

#include "threadUtils.hpp"
#include "datatypes.h"
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "networkAddress.h"

class NetworkPrefix : public NetworkAddress
{
public:
	NetworkPrefix();
	NetworkPrefix(const NetworkAddress &, u_int8_t length);
	NetworkPrefix(const NetworkPrefix &);
	void setNetworkPrefixLength(u_int8_t length );
	u_int8_t getNetworkPrefixLength();
  bool operator<(const NetworkPrefix &s) const;

private:
	operator NetworkAddress();
  void operator=(const NetworkPrefix &s);
	u_int8_t length_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
    ar & length_;
		ar & boost::serialization::base_object<NetworkAddress>(*this);
  };

};

#endif
