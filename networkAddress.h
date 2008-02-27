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

#include "threadUtils.hpp"
#include "datatypes.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	~NetworkAddress();
	void setNetworkAddress(const network_address_type_t type, const char * address );
	void getNetworkAddress(const char *);
	network_address_type_t getNetworkAddressType();
  bool operator<(const NetworkAddress &s) const;

private:
  Mutex mutex_;
	in_addr ipv4_address_;
	in6_addr ipv6_address_;
	uint64_t ethernet_address_;
	network_address_type_t network_address_type_;
};

#endif
