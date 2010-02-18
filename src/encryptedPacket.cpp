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
#include <cstdio>       // for std::memcpy

#include "encryptedPacket.h"
#include "endian.h"
#include "datatypes.h"
#include "log.h"
#include "anytunError.h"

EncryptedPacket::EncryptedPacket(uint32_t payload_length, uint32_t auth_tag_length, bool allow_realloc)
  : Buffer(payload_length + sizeof(struct HeaderStruct), allow_realloc), auth_tag_length_(auth_tag_length)
{
  header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  payload_ = buf_ + sizeof(struct HeaderStruct);
  auth_tag_ = NULL;
  if(header_) {
    header_->seq_nr = 0;
    header_->sender_id = 0;
    header_->mux = 0;
  }
}

uint32_t EncryptedPacket::getHeaderLength()
{
  return sizeof(struct HeaderStruct);
}

seq_nr_t EncryptedPacket::getSeqNr() const
{
  if(header_) {
    return SEQ_NR_T_NTOH(header_->seq_nr);
  }

  return 0;
}

sender_id_t EncryptedPacket::getSenderId() const
{
  if(header_) {
    return SENDER_ID_T_NTOH(header_->sender_id);
  }

  return 0;
}

mux_t EncryptedPacket::getMux() const
{
  if(header_) {
    return MUX_T_NTOH(header_->mux);
  }

  return 0;
}

void EncryptedPacket::setSeqNr(seq_nr_t seq_nr)
{
  if(header_) {
    header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
  }
}

void EncryptedPacket::setSenderId(sender_id_t sender_id)
{
  if(header_) {
    header_->sender_id = SENDER_ID_T_HTON(sender_id);
  }
}

void EncryptedPacket::setMux(mux_t mux)
{
  if(header_) {
    header_->mux = MUX_T_HTON(mux);
  }
}

void EncryptedPacket::setHeader(seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!header_) {
    return;
  }

  header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
  header_->sender_id = SENDER_ID_T_HTON(sender_id);
  header_->mux = MUX_T_HTON(mux);
}

uint32_t EncryptedPacket::getPayloadLength() const
{
  if(!payload_) {
    return 0;
  }

  if(!auth_tag_) {
    return (length_ > sizeof(struct HeaderStruct)) ? (length_ - sizeof(struct HeaderStruct)) : 0;
  }

  return (length_ > (sizeof(struct HeaderStruct) + auth_tag_length_)) ? (length_ - sizeof(struct HeaderStruct) - auth_tag_length_) : 0;
}

void EncryptedPacket::setPayloadLength(uint32_t payload_length)
{
  Buffer::setLength(payload_length + sizeof(struct HeaderStruct));
  // depending on allow_realloc buf_ may point to another address
  // therefore in this case reinit() gets called by Buffer::setLength()
}

void EncryptedPacket::reinit()
{
  header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  payload_ = buf_ + sizeof(struct HeaderStruct);

  if(length_ <= (sizeof(struct HeaderStruct))) {
    payload_ = NULL;
  }

  if(length_ < (sizeof(struct HeaderStruct))) {
    header_ = NULL;
    AnytunError::throwErr() << "encrypted packet can't be initialized, buffer is too small";
  }

  if(auth_tag_) {
    if(length_ < (sizeof(struct HeaderStruct) + auth_tag_length_)) {
      auth_tag_ = NULL;
      AnytunError::throwErr() << "auth-tag can't be enabled, buffer is too small";
    }
    auth_tag_ = buf_ + length_ - auth_tag_length_;
  }
}

uint8_t* EncryptedPacket::getPayload()
{
  return payload_;
}

uint8_t* EncryptedPacket::getAuthenticatedPortion()
{
  return buf_;
}

uint32_t EncryptedPacket::getAuthenticatedPortionLength()
{
  if(!buf_) {
    return 0;
  }

  if(!auth_tag_) {
    return length_;
  }

  return (length_ > auth_tag_length_) ? (length_ - auth_tag_length_) : 0;
}

void EncryptedPacket::withAuthTag(bool b)
{
  if((b && auth_tag_) || (!b && !auth_tag_)) {
    return;
  }

  if(b) {
    if(length_ < (sizeof(struct HeaderStruct) + auth_tag_length_)) {
      AnytunError::throwErr() << "auth-tag can't be enabled, buffer is too small";
    }

    auth_tag_ = buf_ + length_ - auth_tag_length_;
  } else {
    auth_tag_ = NULL;
  }
}

void EncryptedPacket::addAuthTag()
{
  if(auth_tag_) {
    return;
  }

  auth_tag_ = buf_; // will be set to the correct value @ reinit
  setLength(length_ + auth_tag_length_);
  if(auth_tag_ == buf_) { // reinit was not called by setLength
    reinit();
  }
}

void EncryptedPacket::removeAuthTag()
{
  if(!auth_tag_) {
    return;
  }

  auth_tag_ = NULL;
  setLength(length_ - auth_tag_length_);
}

uint8_t* EncryptedPacket::getAuthTag()
{
  return auth_tag_;
}

uint32_t EncryptedPacket::getAuthTagLength()
{
  if(auth_tag_) {
    return auth_tag_length_;
  }

  return 0;
}
