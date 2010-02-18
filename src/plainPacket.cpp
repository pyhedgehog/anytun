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

#include <stdexcept>
#include <iostream>
#include "datatypes.h"
#include "endian.h"
#include "plainPacket.h"
#include "anytunError.h"

PlainPacket::PlainPacket(uint32_t payload_length, bool allow_realloc) : Buffer(payload_length + sizeof(payload_type_t), allow_realloc)
{
  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  payload_ = buf_ + sizeof(payload_type_t);
  *payload_type_ = 0;
}

uint32_t PlainPacket::getHeaderLength()
{
  return sizeof(payload_type_t);
}

payload_type_t PlainPacket::getPayloadType() const
{
  if(payload_type_) {
    return PAYLOAD_TYPE_T_NTOH(*payload_type_);
  }

  return 0;
}

void PlainPacket::setPayloadType(payload_type_t payload_type)
{
  if(!payload_type_) {
    return;
  }

  if(payload_type == PAYLOAD_TYPE_TUN) {
    if(!payload_) {
      *payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN);
      return;
    }

    char* ip_version_ptr = reinterpret_cast<char*>(payload_);
    char ip_version = ip_version_ptr[0];
    ip_version >>=4;
    if(ip_version == 4) {
      *payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN4);
    } else if(ip_version == 6) {
      *payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN6);
    }
  } else {
    *payload_type_ = PAYLOAD_TYPE_T_HTON(payload_type);
  }
}

uint32_t PlainPacket::getPayloadLength() const
{
  if(!payload_) {
    return 0;
  }

  return (length_ > sizeof(payload_type_t)) ? (length_ - sizeof(payload_type_t)) : 0;
}

void PlainPacket::setPayloadLength(uint32_t payload_length)
{
  Buffer::setLength(payload_length + sizeof(payload_type_t));
  // depending on allow_realloc buf_ may point to another address
  // therefore in this case reinit() gets called by Buffer::setLength()
}

void PlainPacket::reinit()
{
  payload_type_ = reinterpret_cast<payload_type_t*>(buf_);
  payload_ = buf_ + sizeof(payload_type_t);

  if(length_ <= (sizeof(payload_type_t))) {
    payload_ = NULL;
  }

  if(length_ < (sizeof(payload_type_t))) {
    payload_type_ = NULL;
    AnytunError::throwErr() << "plain packet can't be initialized, buffer is too small";
  }

}

uint8_t* PlainPacket::getPayload()
{
  return payload_;
}

/*
NetworkAddress PlainPacket::getSrcAddr() const
{
  if(!payload_type_ || !payload_)
    return NetworkAddress();

  payload_type_t type = PAYLOAD_TYPE_T_NTOH(*payload_type_);

  if(type == PAYLOAD_TYPE_TAP) // Ehternet
  {
        // TODO
    return NetworkAddress();
  }
  else if(type == PAYLOAD_TYPE_TUN4) // IPv4
  {
    if(length_ < (sizeof(payload_type_t)+sizeof(struct ip)))
      return NetworkAddress();
    struct ip* hdr = reinterpret_cast<struct ip*>(payload_);
    return NetworkAddress(hdr->ip_src);
  }
  else if(type == PAYLOAD_TYPE_TUN6) // IPv6
  {
    if(length_ < (sizeof(payload_type_t)+sizeof(struct ip6_hdr)))
      return NetworkAddress();
    struct ip6_hdr* hdr = reinterpret_cast<struct ip6_hdr*>(payload_);
    return NetworkAddress(hdr->ip6_src);
  }
  return NetworkAddress();
}*/

NetworkAddress PlainPacket::getDstAddr() const
{
  if(!payload_type_ || !payload_) {
    return NetworkAddress();
  }

  payload_type_t type = PAYLOAD_TYPE_T_NTOH(*payload_type_);

  if(type == PAYLOAD_TYPE_TAP) { // Ehternet
    // TODO
    return NetworkAddress();
  } else if(type == PAYLOAD_TYPE_TUN4) { // IPv4
    if(length_ < (sizeof(payload_type_t)+5*4)) {
      return NetworkAddress();
    }
    char* hdr = reinterpret_cast<char*>(payload_);
    boost::asio::ip::address_v4::bytes_type ip_octets;
    for(int i=0; i<4; i++) {
      ip_octets[i]=hdr[4*4+i];
    }
    return NetworkAddress(boost::asio::ip::address_v4(ip_octets));
  } else if(type == PAYLOAD_TYPE_TUN6) { // IPv6
    if(length_ < (sizeof(payload_type_t)+2*16+2*4)) {
      return NetworkAddress();
    }
    char* hdr = reinterpret_cast<char*>(payload_);
    boost::asio::ip::address_v6::bytes_type ip_octets;
    for(int i=0; i<16; i++) {
      ip_octets[i]=hdr[2*4+16+i];
    }
    return NetworkAddress(boost::asio::ip::address_v6(ip_octets));
  }
  return NetworkAddress();
}
