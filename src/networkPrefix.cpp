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

#include "threadUtils.hpp"
#include "datatypes.h"

#include "networkPrefix.h"


NetworkPrefix::NetworkPrefix(): NetworkAddress(),length_(0)
{
}

NetworkPrefix::NetworkPrefix(const NetworkAddress& src,uint8_t length): NetworkAddress(src),length_(length)
{
}

NetworkPrefix::NetworkPrefix(const NetworkPrefix& src): NetworkAddress(src),length_(src.length_)
{
}

void NetworkPrefix::setNetworkPrefixLength(uint8_t length)
{
  length_ = length;
}

uint8_t NetworkPrefix::getNetworkPrefixLength() const
{
  return length_;
}


bool NetworkPrefix::operator<(const NetworkPrefix& right) const
{
  if(network_address_type_!=right.network_address_type_) {
    return false;
  }
  if(right.length_!=length_) {
    return (length_<right.length_);
  }
  return static_cast<NetworkAddress>(*this)<static_cast<NetworkAddress>(right);
}

