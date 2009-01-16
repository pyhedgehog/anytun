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

#include <boost/asio.hpp>

#include "datatypes.h"
#include "packetSource.h"

UDPPacketSource::UDPPacketSource(std::string port) : sock_(io_service_)
{
  proto::resolver resolver(io_service_);
  proto::resolver::query query(port);  
  proto::endpoint e = *resolver.resolve(query);
  sock_.open(e.protocol());
  sock_.bind(e);
}

UDPPacketSource::UDPPacketSource(std::string localaddr, std::string port) : sock_(io_service_)
{
  proto::resolver resolver(io_service_);
  proto::resolver::query query(localaddr, port);  
  proto::endpoint e = *resolver.resolve(query);
  sock_.open(e.protocol());
  sock_.bind(e);  
}

u_int32_t UDPPacketSource::recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote)
{
  return static_cast<u_int32_t>(sock_.receive_from(boost::asio::buffer(buf, len), remote));
}

void UDPPacketSource::send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote)
{
  sock_.send_to(boost::asio::buffer(buf, len), remote);
}

