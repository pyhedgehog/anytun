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

NetworkAddress::NetworkAddress()
{
	network_address_type_=ipv4;
	ipv4_address_.s_addr=0;
}

NetworkAddress::NetworkAddress(const NetworkAddress & ref) : mutex_(),ipv4_address_(ref.ipv4_address_),ipv6_address_(ref.ipv6_address_),ethernet_address_(ref.ethernet_address_),network_address_type_(ref.network_address_type_)
{
}

NetworkAddress::NetworkAddress(in6_addr ipv6_address)
{
	network_address_type_=ipv6;
	ipv6_address_ = ipv6_address;
}

NetworkAddress::NetworkAddress(in_addr ipv4_address)
{
	network_address_type_=ipv4;
	ipv4_address_ = ipv4_address;
}

NetworkAddress::NetworkAddress(uint64_t ethernet_address)
{
	network_address_type_=ethernet;
	ethernet_address_=ethernet_address;
}


NetworkAddress::~NetworkAddress()
{
}

NetworkAddress::NetworkAddress(const network_address_type_t type, const char * address )
{
	setNetworkAddress( type, address);
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

std::string NetworkAddress::toString() const
{
	if (network_address_type_==ipv4){
    char buf[INET_ADDRSTRLEN];
    if(!inet_ntop(AF_INET, &ipv4_address_, buf, sizeof(buf)))
      return std::string("");
    return std::string(buf);
	} 
  else if (network_address_type_==ipv6) {
    char buf[INET6_ADDRSTRLEN];
    if(!inet_ntop(AF_INET6, &ipv6_address_, buf, sizeof(buf)))
      return std::string("");
    return std::string(buf);
	} 
  else if (network_address_type_==ethernet) {
        // TODO
	} 
  return std::string("");
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
#if defined(__GNUC__) && defined(__linux__)
			if (ipv6_address_.s6_addr32[i]<right.ipv6_address_.s6_addr32[i])
#elif defined(__GNUC__) && defined(__OpenBSD__)
			if (ipv6_address_.__u6_addr.__u6_addr32[i]<right.ipv6_address_.__u6_addr.__u6_addr32[i])
#else
 #error Target not supported
#endif
				return true;
		return false;
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
	return false;
}


NetworkAddress NetworkAddress::operator<<(uint8_t shift) const
{
	if (network_address_type_==ipv4)
	{
		in_addr new_v4_addr;
		new_v4_addr.s_addr = ipv4_address_.s_addr << shift;
		return (NetworkAddress(new_v4_addr));
	} else if (network_address_type_==ipv6) {
		in6_addr new_v6_addr;
		for(int i=0;i<4;i++)
		{
#if defined(__GNUC__) && defined(__linux__)
			new_v6_addr.s6_addr32[i]=ipv6_address_.s6_addr32[i]<<1;
			if (i<3 && (ipv6_address_.s6_addr32[i+1] & uint32_t (0x80000000)))
				new_v6_addr.s6_addr32[i] &=1;
#elif defined(__GNUC__) && defined(__OpenBSD__)
			new_v6_addr.__u6_addr.__u6_addr32[i]=ipv6_address_.__u6_addr.__u6_addr32[i]<<1;
      if (i<3 && (ipv6_address_.__u6_addr.__u6_addr32[i+1] & uint32_t (0x80000000)))
				new_v6_addr.__u6_addr.__u6_addr32[i] &=1;
#else
 #error Target not supported
#endif

		}
		return NetworkAddress(new_v6_addr);
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
	return false;
}

NetworkAddress NetworkAddress::operator&(const NetworkAddress &right) const
{
	if (network_address_type_!=right.network_address_type_)
		throw std::runtime_error("network_address_types did not match");
	if (network_address_type_==ipv4)
	{
		in_addr new_v4_addr;
		new_v4_addr.s_addr = ipv4_address_.s_addr & right.ipv4_address_.s_addr;
		return (NetworkAddress(new_v4_addr));
	} else if (network_address_type_==ipv6) {
		in6_addr new_v6_addr;
		for(int i=0;i<4;i++)
#if defined(__GNUC__) && defined(__linux__)
			new_v6_addr.s6_addr32[i]=ipv6_address_.s6_addr32[i]&right.ipv6_address_.s6_addr32[i];
#elif defined(__GNUC__) && defined(__OpenBSD__)
      new_v6_addr.__u6_addr.__u6_addr32[i]=ipv6_address_.__u6_addr.__u6_addr32[i]&right.ipv6_address_.__u6_addr.__u6_addr32[i];
#else
 #error Target not supported
#endif

		return NetworkAddress(new_v6_addr);
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
	return false;
}

NetworkAddress NetworkAddress::operator&=(const NetworkAddress &right)
{
	if (network_address_type_!=right.network_address_type_)
		throw std::runtime_error("network_address_types did not match");
	if (network_address_type_==ipv4)
	{
		ipv4_address_.s_addr &= right.ipv4_address_.s_addr;
		return *this;
	} else if (network_address_type_==ipv6) {
		for(int i=0;i<4;i++)
#if defined(__GNUC__) && defined(__linux__)
			ipv6_address_.s6_addr32[i]&=right.ipv6_address_.s6_addr32[i];
#elif defined(__GNUC__) && defined(__OpenBSD__)
			ipv6_address_.__u6_addr.__u6_addr32[i]&=right.ipv6_address_.__u6_addr.__u6_addr32[i];
#else
 #error Target not supported
#endif

		return *this;
	} else if (network_address_type_==ethernet) {
		//TODO
	} else {
		//TODO
	}
	return false;
}
