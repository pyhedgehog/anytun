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

#ifndef _NETWORK_ADDRESS_H
#define _NETWORK_ADDRESS_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"
#include "datatypes.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>

enum network_address_type_t
{
	ipv4,
	ipv6,
	ethernet
};

class NetworkAddress
{
public:
	NetworkAddress();
	NetworkAddress(const NetworkAddress &);
	NetworkAddress(in6_addr);
	NetworkAddress(in_addr);
	NetworkAddress(uint64_t);
	~NetworkAddress();
	void setNetworkAddress(const network_address_type_t type, const char * address );
	void getNetworkAddress(const char *);
	network_address_type_t getNetworkAddressType();
  std::string toString() const;
  bool operator<(const NetworkAddress &s) const;
  NetworkAddress operator&(const NetworkAddress &s) const;
  NetworkAddress operator&=(const NetworkAddress &s);
  NetworkAddress operator<<(uint8_t shift) const;

protected:
  Mutex mutex_;
	in_addr ipv4_address_;
	in6_addr ipv6_address_;
	uint64_t ethernet_address_;
	network_address_type_t network_address_type_;
private:
	NetworkAddress operator=(const NetworkAddress &s);
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
    ar & network_address_type_;
		if (network_address_type_==ipv4)
			ar & ipv4_address_.s_addr;
		if (network_address_type_==ipv6)
			for(int i=0;i<4;i++)
				ar & ipv6_address_.s6_addr32;
		if (network_address_type_==ethernet_address_)
			ar & ethernet_address_;
   }
};

#endif
