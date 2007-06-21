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

#include "datatypes.h"

#include "packetSource.h"
#include "buffer.h"
#include "PracticalSocket.h"

UDPPacketSource::UDPPacketSource()
{
}

UDPPacketSource::UDPPacketSource(u_int16_t port) : UDPSocket(port)
{
}

UDPPacketSource::UDPPacketSource(std::string localaddr, u_int16_t port) : UDPSocket(localaddr, port)
{
}

u_int32_t UDPPacketSource::recv(Buffer& buf, std::string addr, u_int16_t &port)
{
  return recvFrom(buf, buf.getLength(), addr, port);
}

void UDPPacketSource::send(Buffer& buf, std::string addr, u_int16_t port)
{
  sendTo(buf, buf.getLength(), addr, port);
}
