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

#include "threadUtils.hpp"
#include "datatypes.h"
#include <exception>

#include "networkAddress.h"

NetworkAddress::NetworkAddress():ipv4_address_(),ipv6_address_()
{
	network_address_type_=ipv4;
}

NetworkAddress::NetworkAddress(const NetworkAddress & ref) : mutex_(),ipv4_address_(ref.ipv4_address_),ipv6_address_(ref.ipv6_address_),ethernet_address_(ref.ethernet_address_),network_address_type_(ref.network_address_type_)
{
}

NetworkAddress::NetworkAddress(const std::string & address)
{
	boost::asio::ip::address addr = boost::asio::ip::address::from_string(address);
	if (addr.is_v4())
	{
		network_address_type_=ipv4;
		ipv4_address_ = addr.to_v4();
	} else {
		network_address_type_=ipv6;
		ipv6_address_ = addr.to_v6();
	}
}

NetworkAddress::NetworkAddress(boost::asio::ip::address_v6 ipv6_address)
{
	network_address_type_=ipv6;
	ipv6_address_ = ipv6_address;
}

NetworkAddress::NetworkAddress(boost::asio::ip::address_v4 ipv4_address)
{
	network_address_type_=ipv4;
	ipv4_address_ = ipv4_address;
}

NetworkAddress::NetworkAddress(u_int64_t ethernet_address)
{
	network_address_type_=ethernet;
	ethernet_address_=ethernet_address;
}


NetworkAddress::~NetworkAddress()
{
}

NetworkAddress::NetworkAddress(const network_address_type_t type, const std::string & address )
{
	setNetworkAddress( type, address);
}

void NetworkAddress::setNetworkAddress(const network_address_type_t type, const std::string & address )
{
	if (type==ipv4)
	{
		ipv4_address_=boost::asio::ip::address_v4::from_string(address);
	} else if (type==ipv6) {
		ipv6_address_=boost::asio::ip::address_v6::from_string(address);
	} else if (type==ethernet) {
		//TODO
	} else {
		//TODO
	}
	network_address_type_ = type;
}

network_address_type_t NetworkAddress::getNetworkAddressType() const
{
	return network_address_type_;
}

std::string NetworkAddress::toString() const
{
	if (network_address_type_==ipv4){
		return ipv4_address_.to_string();
	} 
  else if (network_address_type_==ipv6) {
		return ipv6_address_.to_string();
	} 
  else if (network_address_type_==ethernet) {
        // TODO
	} 
  return std::string("");
}

ipv4_bytes_type	NetworkAddress::to_bytes_v4() const
{
	return ipv4_address_.to_bytes();
}

ipv6_bytes_type	NetworkAddress::to_bytes_v6() const
{
	return ipv6_address_.to_bytes();
}

ethernet_bytes_type	NetworkAddress::to_bytes_ethernet() const
{
	boost::array<unsigned char,6> result;
	u_int64_t ether=ethernet_address_;
	for (int i = 0; i < 6; i++)
	{
		result[i] = (unsigned char) (ether && 0xff);
			ether >>= 8;
	}
	return result;
}

bool NetworkAddress::operator<(const NetworkAddress &right) const
{
	if (network_address_type_!=right.network_address_type_)
		throw std::runtime_error("NetworkAddress::operator<() address types don't match");
	if (network_address_type_==ipv4)
	{
		return (ipv4_address_ < right.ipv4_address_);
	} else if (network_address_type_==ipv6) {
		return (ipv6_address_ < right.ipv6_address_);
	} else if (network_address_type_==ethernet) {
		 return (ethernet_address_ < right.ethernet_address_);
	} else {
		//TODO
	}
	return false;
}

