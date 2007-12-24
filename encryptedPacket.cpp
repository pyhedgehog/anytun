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
#include <cstdio>       // for std::memcpy

#include "encryptedPacket.h"
#include "datatypes.h"
#include "authTag.h"
#include "log.h"


EncryptedPacket::EncryptedPacket(u_int32_t max_payload_length) 
        : Buffer(max_payload_length + sizeof(struct HeaderStruct) + AUTHTAG_SIZE)
{
  header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  auth_tag_ = NULL;
  buf_ = buf_ + sizeof(struct HeaderStruct);    // no authtag yet
  length_ = length_ - sizeof(struct HeaderStruct);
  size_ = max_payload_length + AUTHTAG_SIZE;
}


seq_nr_t EncryptedPacket::getSeqNr() const
{
  return SEQ_NR_T_NTOH(header_->seq_nr);
}

sender_id_t EncryptedPacket::getSenderId() const
{
  return SENDER_ID_T_NTOH(header_->sender_id);
}

mux_t EncryptedPacket::getMux() const
{
  return MUX_T_NTOH(header_->mux);
}

u_int32_t EncryptedPacket::getSize() const
{
  return size_;
}

void EncryptedPacket::setLength(u_int32_t length)
{
  if(length > size_)
    throw std::out_of_range("can't set length greater then size ofsize of  allocated memory");

  length_ = length;
}

void EncryptedPacket::setSeqNr(seq_nr_t seq_nr)
{
  header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
}

void EncryptedPacket::setSenderId(sender_id_t sender_id)
{
  header_->sender_id = SENDER_ID_T_HTON(sender_id);
}

void EncryptedPacket::setMux(mux_t mux)
{
  header_->mux = MUX_T_HTON(mux);
}

void EncryptedPacket::setHeader(seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
  header_->sender_id = SENDER_ID_T_HTON(sender_id);
  header_->mux = MUX_T_HTON(mux);
}

bool EncryptedPacket::hasAuthTag() const
{
  if( auth_tag_ == NULL )
    return false;
  return true;
}

void EncryptedPacket::withAuthTag(bool b)
{
  if( b && (auth_tag_ != NULL) )
    throw std::runtime_error("packet already has auth tag function enabled");

  if( b ) {
    auth_tag_ = reinterpret_cast<AuthTag*>( buf_ + sizeof(struct HeaderStruct) );
    buf_ = buf_ + AUTHTAG_SIZE;
    length_ -= AUTHTAG_SIZE;
    size_ -= AUTHTAG_SIZE;
  } else {
    buf_ = reinterpret_cast<u_int8_t*>( auth_tag_ );
    length_ += AUTHTAG_SIZE;
    size_ += AUTHTAG_SIZE;
    auth_tag_ = NULL;
  }
}

void EncryptedPacket::setAuthTag(AuthTag& tag)
{
  if( auth_tag_ == NULL )
    throw std::runtime_error("auth tag not enabled");

  if( tag == AuthTag(0) )
    return;

  if( tag.getLength() != AUTHTAG_SIZE )
    throw std::length_error("authtag length mismatch with AUTHTAG_SIZE");

  std::memcpy( auth_tag_, tag.getBuf(), AUTHTAG_SIZE );
}

AuthTag EncryptedPacket::getAuthTag() const
{
  if( auth_tag_ == NULL )
    throw std::runtime_error("auth tag not enabled");

  AuthTag at(AUTHTAG_SIZE);
  std::memcpy(at, auth_tag_, AUTHTAG_SIZE );
  return at;
}


//Packet& Packet::addHeader(seq_nr_t seq_nr, sender_id_t sender_id)
//{
//  if(!has_header_)
//  {
//    if(sizeof(struct HeaderStruct) > resizeFront(length_ + sizeof(struct HeaderStruct)))
//      return *this;
//
//    has_header_ = true;
//  }
//  struct HeaderStruct* header;
//  header = reinterpret_cast<struct HeaderStruct*>(buf_);
//  header->seq_nr = SEQ_NR_T_HTON(seq_nr);
//  header->sender_id = SENDER_ID_T_HTON(sender_id);
//  return *this;
//}
//
//
//bool Packet::hasPayloadType() const
//{
//  return has_payload_type_;
//}
//
//Packet& Packet::withPayloadType(bool b)
//{
//  if(b && length_ >= sizeof(payload_type_t))
//    has_payload_type_ = true;
//  else
//    has_payload_type_ = false;
//
//  return *this;
//}
//
//payload_type_t Packet::getPayloadType() const
//{
//  if(!has_payload_type_)
//    return 0;
//
//  if((!has_auth_tag_ && length_ < sizeof(payload_type_t)) ||
//     (has_auth_tag_ && length_ < (sizeof(payload_type_t) + AUTHTAG_SIZE)))
//    return 0;
//
//  payload_type_t* payload_type;
//
//  if(!has_auth_tag_)  
//    payload_type = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t));
//  else
//    payload_type = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t) - AUTHTAG_SIZE);
//  return PAYLOAD_TYPE_T_NTOH(*payload_type);
//}
//
//Packet& Packet::addPayloadType(payload_type_t payload_type)
//{
//  if(has_auth_tag_)
//    throw std::runtime_error("can't add payload_type with existing auth_tag");
//
//  if(!has_payload_type_)
//  {
//    u_int32_t new_length = length_ + sizeof(payload_type_t);
//    if(new_length > resizeBack(new_length))
//      return *this;
//
//    has_payload_type_ = true;
//  }
//  payload_type_t* payload_type_ptr;
//  payload_type_ptr = reinterpret_cast<payload_type_t*>(buf_ + length_ - sizeof(payload_type_t));
//  *payload_type_ptr = PAYLOAD_TYPE_T_HTON(payload_type);
//  return *this;
//}
//
//Packet& Packet::removePayloadType()
//{
//  if(has_auth_tag_)
//    throw std::runtime_error("can't remove payload_type with existing auth_tag");
//
//  if(!has_payload_type_)
//    return *this;
//
//  if(length_ >= sizeof(payload_type_t))
//    resizeBack(length_ - sizeof(payload_type_t));
//
//  has_payload_type_ = false;
//  
//  return *this;
//}
//
//
//
//
//AuthTag Packet::getAuthTag() const
//{
//  if(!has_auth_tag_)
//    return AuthTag(0);
//
//  if(length_ < AUTHTAG_SIZE)
//    return AuthTag(0);
//
//  //AuthTag* auth_tag;
//  //auth_tag = reinterpret_cast<AuthTag*>(buf_ + length_ - AUTHTAG_SIZE);
//  //return AUTH_TAG_T_NTOH(*auth_tag);
//  AuthTag auth_tag;
//  auth_tag = AuthTag(buf_ + length_ - AUTHTAG_SIZE, AUTHTAG_SIZE);
//  return auth_tag;
//}
//
//Packet& Packet::addAuthTag(AuthTag auth_tag)
//{
//  if(!has_auth_tag_)
//  {
//    u_int32_t new_length = length_ + auth_tag.getLength();
//    if(new_length > resizeBack(new_length))
//      return *this;
//
//    has_auth_tag_ = true;
//  }
//
//  AuthTag* auth_tag_ptr;
//  auth_tag_ptr = reinterpret_cast<AuthTag*>(buf_ + length_ - auth_tag.getLength());
//  std::memcpy(auth_tag_ptr, auth_tag.getBuf(), auth_tag.getLength());
//
//  return *this;
//}
//
//Packet& Packet::removeAuthTag()
//{
//  if(!has_auth_tag_)
//    return *this;
//
//  if(length_ >= AUTHTAG_SIZE)
//    resizeBack(length_ - AUTHTAG_SIZE);
//
//  has_auth_tag_ = false;
//  
//  return *this;
//}
//
