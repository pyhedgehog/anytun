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

UDPPacketSource::UDPPacketSource(std::string localaddr, std::string port)
{
  gResolver.resolveUdp(localaddr, port, boost::bind(&UDPPacketSource::onResolve, this, _1), boost::bind(&UDPPacketSource::onError, this, _1), gOpt.getResolvAddrType());
}

UDPPacketSource::~UDPPacketSource()
{
  std::list<proto::socket*>::iterator it = sockets_.begin();
  for(;it != sockets_.end(); ++it)
    delete *it;
}

void UDPPacketSource::onResolve(PacketSourceResolverIt& it)
{
  while(it != PacketSourceResolverIt()) {
    PacketSourceEndpoint e = *it;
    cLog.msg(Log::PRIO_NOTICE) << "opening socket: " << e;

    proto::socket* sock = new proto::socket(io_service_);
    sock->open(e.protocol());
    if(e.protocol() == proto::v6()) {
      boost::asio::ip::v6_only option(true);
      sock->set_option(option);
    }
    sock->bind(e);
    sockets_.push_back(sock);

    it++;
  }

  ready_sem_.up();
}

void UDPPacketSource::onError(const std::runtime_error& e)
{
  gSignalController.inject(SIGERROR, e.what());
}

u_int32_t UDPPacketSource::recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote)
{
  return static_cast<u_int32_t>(sockets_.front()->receive_from(boost::asio::buffer(buf, len), remote));
}

void UDPPacketSource::send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote)
{
  sockets_.front()->send_to(boost::asio::buffer(buf, len), remote);
}

