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

#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>

#include "datatypes.h"

#include "plainPacket.h"



PlainPacket::~PlainPacket()
{
  buf_ = reinterpret_cast<u_int8_t*>(payload_type_);
  length_ = size_;
}

PlainPacket::PlainPacket(u_int32_t max_payload_length) : Buffer(max_payload_length + sizeof(payload_type_t))
{
  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  buf_ += sizeof(payload_type_t);
  length_ = max_payload_length;
  size_ = length_;
}

payload_type_t PlainPacket::getPayloadType() const
{
  return PAYLOAD_TYPE_T_NTOH(*payload_type_);
}

void PlainPacket::setPayloadType(payload_type_t payload_type)
{
  payload_type = PAYLOAD_TYPE_T_HTON(payload_type);
}

void PlainPacket::setLength(u_int32_t length)
{
  if(length > size_)
    throw std::out_of_range("can't set length greater then size ofsize of  allocated memory");

  length_ = length;
}

u_int32_t PlainPacket::getSize() const
{
  return size_;
}
