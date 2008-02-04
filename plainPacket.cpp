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
	buf_=complete_payload_;
	length_=max_length_;
}

PlainPacket::PlainPacket(u_int32_t max_payload_length) : Buffer(max_payload_length + sizeof(payload_type_t))
{
	splitPayload();
}

void PlainPacket::splitPayload()
{
  complete_payload_length_ = length_;
	complete_payload_ = buf_;

  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  buf_ += sizeof(payload_type_t);
  length_ -= sizeof(payload_type_t);
  max_length_ = length_;
}

void PlainPacket::setCompletePayloadLength(u_int32_t payload_length)
{
	complete_payload_length_ = payload_length;
	length_=complete_payload_length_-sizeof(payload_type_t);
}

payload_type_t PlainPacket::getPayloadType() const
{
  return PAYLOAD_TYPE_T_NTOH(*payload_type_);
}

void PlainPacket::setPayloadType(payload_type_t payload_type)
{
  payload_type_ = PAYLOAD_TYPE_T_HTON(payload_type);
}

void PlainPacket::setLength(u_int32_t length)
{
  if(length > max_length_)
    throw std::out_of_range("can't set length greater then size ofsize of  allocated memory");

  length_ = length;
	complete_payload_length_ = length_ + sizeof(payload_type_t);
}

u_int32_t PlainPacket::getMaxLength() const
{
  return max_length_;
}
