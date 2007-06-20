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
#include <arpa/inet.h>

#include "datatypes.h"

#include "packet.h"

Packet::Packet()
{
  has_header_ = false;
  has_payload_type_ = false;
  has_auth_tag_ = false;                
}

Packet::Packet(u_int32_t length) : Buffer(length)
{
  has_header_ = false;
  has_payload_type_ = false;
  has_auth_tag_ = false;                
}

Packet::Packet(const Buffer &src) : Buffer(src)
{
  has_header_ = false;
  has_payload_type_ = false;
  has_auth_tag_ = false;                
}
  
bool Packet::hasHeader() const
{
  return has_header_;
}

Packet& Packet::withHeader(bool b)
{
  if(b && length_ >= sizeof(struct HeaderStruct))
    has_header_ = true;
  else
    has_header_ = false;

  return *this;
}

seq_nr_t Packet::getSeqNr() const
{
  if(!has_header_)
    return 0;

  struct HeaderStruct* header;
  header = reinterpret_cast<struct HeaderStruct*>(buf_);
  return SEQ_NR_T_NTOH(header->seq_nr);
}

sender_id_t Packet::getSenderId() const
{
  if(!has_header_)
    return 0;

  struct HeaderStruct* header;
  header = reinterpret_cast<struct HeaderStruct*>(buf_);
  return SENDER_ID_T_NTOH(header->sender_id);
}

Packet& Packet::addHeader(seq_nr_t seq_nr, sender_id_t sender_id)
{
  if(!has_header_)
  {
    if(sizeof(struct HeaderStruct) > resizeFront(length_ + sizeof(struct HeaderStruct)))
      return *this;

    has_header_ = true;
  }
  struct HeaderStruct* header;
  header = reinterpret_cast<struct HeaderStruct*>(buf_);
  header->seq_nr = SEQ_NR_T_HTON(seq_nr);
  header->sender_id = SENDER_ID_T_HTON(sender_id);
  return *this;
}

Packet& Packet::removeHeader()
{
  if(!has_header_)
    return *this;

  if(length_ >= sizeof(struct HeaderStruct))
    resizeFront(length_ - sizeof(struct HeaderStruct));

  has_header_ = false;
  
  return *this;
}

Packet& Packet::setSeqNr(seq_nr_t seq_nr)
{
  if(has_header_)
  {
    struct HeaderStruct* header;
    header = reinterpret_cast<struct HeaderStruct*>(buf_);
    header->seq_nr = SEQ_NR_T_HTON(seq_nr);
  }
  return *this;
}

Packet& Packet::setSenderId(sender_id_t sender_id)
{
  if(has_header_)
  {
    struct HeaderStruct* header;
    header = reinterpret_cast<struct HeaderStruct*>(buf_);
    header->sender_id = SENDER_ID_T_HTON(sender_id);
  }
  return *this;
}



bool Packet::hasPayloadType() const
{
  return has_payload_type_;
}

Packet& Packet::withPayloadType(bool b)
{
  if(b && length_ >= sizeof(payload_type_t))
    has_payload_type_ = true;
  else
    has_payload_type_ = false;

  return *this;
}

payload_type_t Packet::getPayloadType() const
{
  if(!has_payload_type_)
    return 0;

  if((!has_auth_tag_ && length_ < sizeof(payload_type_t)) ||
     (has_auth_tag_ && length_ < (sizeof(payload_type_t) + sizeof(auth_tag_t))))
    return 0;

  payload_type_t* payload_type;

  if(!has_auth_tag_)  
    payload_type = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t));
  else
    payload_type = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t) - sizeof(auth_tag_t));
  return PAYLOAD_TYPE_T_NTOH(*payload_type);
}

Packet& Packet::addPayloadType(payload_type_t payload_type)
{
  if(has_auth_tag_)
    throw std::runtime_error("can't add payload_type with existing auth_tag");

  if(!has_payload_type_)
  {
    u_int32_t new_length = length_ + sizeof(payload_type_t);
    if(new_length > resizeBack(new_length))
      return *this;

    has_payload_type_ = true;
  }
  payload_type_t* payload_type_ptr;
  payload_type_ptr = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t));
  *payload_type_ptr = PAYLOAD_TYPE_T_HTON(payload_type);
  return *this;
}

Packet& Packet::removePayloadType()
{
  if(has_auth_tag_)
    throw std::runtime_error("can't remove payload_type with existing auth_tag");

  if(!has_payload_type_)
    return *this;

  if(length_ >= sizeof(payload_type_t))
    resizeBack(length_ - sizeof(payload_type_t));

  has_payload_type_ = false;
  
  return *this;
}



bool Packet::hasAuthTag() const
{
  return has_auth_tag_;
}

Packet& Packet::withAuthTag(bool b)
{
  if(b && length_ >= sizeof(auth_tag_t))
    has_auth_tag_ = true;
  else
    has_auth_tag_ = false;
  
  return *this;
}  

auth_tag_t Packet::getAuthTag() const
{
  if(!has_auth_tag_)
    return 0;

  if(length_ < sizeof(auth_tag_t))
    return 0;

  auth_tag_t* auth_tag;
  auth_tag = reinterpret_cast<auth_tag_t*>(buf_ + length_ - sizeof(auth_tag_t));
  return AUTH_TAG_T_NTOH(*auth_tag);
}

Packet& Packet::addAuthTag(auth_tag_t auth_tag)
{
  if(!has_auth_tag_)
  {
    u_int32_t new_length = length_ + sizeof(auth_tag_t);
    if(new_length > resizeBack(new_length))
      return *this;

    has_auth_tag_ = true;
  }
  auth_tag_t* auth_tag_ptr;
  auth_tag_ptr = reinterpret_cast<auth_tag_t*>(buf_ + length_ - sizeof(auth_tag_t));
  *auth_tag_ptr = AUTH_TAG_T_HTON(auth_tag);
  return *this;
}

Packet& Packet::removeAuthTag()
{
  if(!has_auth_tag_)
    return *this;

  if(length_ >= sizeof(auth_tag_t))
    resizeBack(length_ - sizeof(auth_tag_t));

  has_auth_tag_ = false;
  
  return *this;
}
