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


PlainPacket::PlainPacket(u_int32_t payload_length, bool allow_realloc) : Buffer(payload_length + sizeof(payload_type_t), allow_realloc)
{
  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  payload_ = buf_ + sizeof(payload_type_t);
  *payload_type_ = 0;
}

payload_type_t PlainPacket::getPayloadType() const
{
  if(payload_type_)
    return PAYLOAD_TYPE_T_NTOH(*payload_type_);

  return 0;
}

void PlainPacket::setPayloadType(payload_type_t payload_type)
{
  if(payload_type_)
    *payload_type_ = PAYLOAD_TYPE_T_HTON(payload_type);
}

u_int32_t PlainPacket::getPayloadLength() const
{
  return (length_ > sizeof(payload_type_t)) ? (length_ - sizeof(payload_type_t)) : 0;
}
    
void PlainPacket::setPayloadLength(u_int32_t payload_length)
{
  Buffer::setLength(payload_length + sizeof(payload_type_t));
      // depending on allow_realloc buf_ may point to another address
      // therefore in this case reinit() gets called by Buffer::setLength()
}

void PlainPacket::reinit()
{
  Buffer::reinit();
  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  payload_ = buf_ + sizeof(payload_type_t);
}

u_int8_t* PlainPacket::getPayload()
{
  return payload_;
}
