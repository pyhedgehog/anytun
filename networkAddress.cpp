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

#include "networkAddress.h"

NetworkAddress::NetworkAddress()
{
}

NetworkAddress::~NetworkAddress()
{
}

void NetworkAddress::setNetworkAddress(const network_address_type_t type, const char * address )
{
	if (type==ipv4)
	{
		inet_pton(AF_INET, address, &ipv4_address_);
	} else if (type==ipv6) {
		inet_pton(AF_INET6, address, &ipv6_address_);
	} else if (type==ethernet) {
		//TODO
	} else {
		//TODO
	}
	network_address_type_ = type;
}

void NetworkAddress::getNetworkAddress(const char *)
{
}

network_address_type_t NetworkAddress::getNetworkAddressType()
{
	return network_address_type_;
}

bool NetworkAddress::operator<(const NetworkAddress &right) const
{
	if (network_address_type_!=right.network_address_type_)
		return false;
	if (network_address_type_==ipv4)
	{
		return (ipv4_address_.s_addr < right.ipv4_address_.s_addr);
	} else if (network_address_type_==ipv6) {
		for(int i=0;i<4;i++)
			if (ipv6_address_.s6_addr32[i]<right.ipv6_address_.s6_addr32[i])
				return true;
		return false;
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
	return false;
}

