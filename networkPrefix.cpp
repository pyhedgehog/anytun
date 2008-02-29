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

#include "threadUtils.hpp"
#include "datatypes.h"

#include "networkPrefix.h"


NetworkPrefix::NetworkPrefix(): NetworkAddress(),length_(0)
{
}

NetworkPrefix::NetworkPrefix(const NetworkAddress & src): NetworkAddress(src),length_(0)
{
}

NetworkPrefix::NetworkPrefix(const NetworkPrefix & src): NetworkAddress(src),length_(src.length_)
{
}

void NetworkPrefix::setNetworkPrefixLength(uint8_t length )
{
	length_ = length;
	if (network_address_type_==ipv4)
	{ 
		in_addr v4addr;
		v4addr.s_addr=0xFFFFFFFF;
		*this &= (NetworkAddress(v4addr)<<(32-length));
	} else if (network_address_type_==ipv6) {
		in6_addr v6addr;
		for(int i=0;i<4;i++)
			ipv6_address_.s6_addr32[i]=0xFFFFFFFF;
		*this &= (NetworkAddress(v6addr)<<(128-length));
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
}

uint8_t NetworkPrefix::getNetworkPrefixLength()
{
	return length_;
}


bool NetworkPrefix::operator<(const NetworkPrefix &right) const
{
	if (network_address_type_!=right.network_address_type_)
		return false;
	if (NetworkAddress::operator<(static_cast<NetworkAddress>(right)))
		return true;
	static_cast<NetworkAddress>(right)<static_cast<NetworkAddress>(*this);
	return (right.length_<length_);
}

