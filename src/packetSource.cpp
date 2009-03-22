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
#include <boost/bind.hpp>

#include "datatypes.h"
#include "packetSource.h"
#include "log.h"
#include "resolver.h"
#include "options.h"
#include "signalController.h"

void PacketSource::waitUntilReady()
{
  ready_sem_.down();
}

UDPPacketSource::UDPPacketSource(std::string port) : sock_(io_service_)
{
  gResolver.resolveUdp("", port, boost::bind(&UDPPacketSource::onResolve, this, _1), boost::bind(&UDPPacketSource::onError, this, _1), gOpt.getResolvAddrType());
}

UDPPacketSource::UDPPacketSource(std::string localaddr, std::string port) : sock_(io_service_)
{
  gResolver.resolveUdp(localaddr, port, boost::bind(&UDPPacketSource::onResolve, this, _1), boost::bind(&UDPPacketSource::onError, this, _1), gOpt.getResolvAddrType());
}

void UDPPacketSource::onResolve(const boost::asio::ip::udp::endpoint& e)
{
  cLog.msg(Log::PRIO_NOTICE) << "opening socket: " << e;
  sock_.open(e.protocol());
  sock_.bind(e);
  ready_sem_.up();
}

void UDPPacketSource::onError(const std::runtime_error& e)
{
  gSignalController.inject(SIGERROR, e.what());
}

u_int32_t UDPPacketSource::recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote)
{
  return static_cast<u_int32_t>(sock_.receive_from(boost::asio::buffer(buf, len), remote));
}

void UDPPacketSource::send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote)
{
  sock_.send_to(boost::asio::buffer(buf, len), remote);
}

