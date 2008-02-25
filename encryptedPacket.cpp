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

// TODO: fix auth_tag stuff
EncryptedPacket::EncryptedPacket(u_int32_t payload_length, bool allow_realloc)
  : Buffer(payload_length + sizeof(struct HeaderStruct), allow_realloc)
{
  header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  payload_ = buf_ + sizeof(struct HeaderStruct);    // TODO: fix auth_tag stuff
  auth_tag_ = NULL;                                 // TODO: fix auth_tag stuff
  if(header_)
  {
    header_->seq_nr = 0;
    header_->sender_id = 0;
    header_->mux = 0;
  }
}

seq_nr_t EncryptedPacket::getSeqNr() const
{
  if(header_)
    return SEQ_NR_T_NTOH(header_->seq_nr);
  
  return 0;
}

sender_id_t EncryptedPacket::getSenderId() const
{
  if(header_)
    return SENDER_ID_T_NTOH(header_->sender_id);

  return 0;
}

mux_t EncryptedPacket::getMux() const
{
  if(header_)
    return MUX_T_NTOH(header_->mux);

  return 0;
}

void EncryptedPacket::setSeqNr(seq_nr_t seq_nr)
{
  if(header_)
    header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
}

void EncryptedPacket::setSenderId(sender_id_t sender_id)
{
  if(header_)
    header_->sender_id = SENDER_ID_T_HTON(sender_id);
}

void EncryptedPacket::setMux(mux_t mux)
{
  if(header_)
    header_->mux = MUX_T_HTON(mux);
}

void EncryptedPacket::setHeader(seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!header_)
    return;

  header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
  header_->sender_id = SENDER_ID_T_HTON(sender_id);
  header_->mux = MUX_T_HTON(mux);
}

u_int32_t EncryptedPacket::getPayloadLength() const
{
  return (length_ > sizeof(struct HeaderStruct)) ? (length_ - sizeof(struct HeaderStruct)) : 0;  // TODO: fix auth_tag stuff
}

void EncryptedPacket::setPayloadLength(u_int32_t payload_length)
{
  Buffer::setLength(payload_length + sizeof(struct HeaderStruct));
      // depending on allow_realloc buf_ may point to another address
      // therefore in this case reinit() gets called by Buffer::setLength()
}

void EncryptedPacket::reinit()
{
  Buffer::reinit();
  header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  payload_ = buf_ + sizeof(struct HeaderStruct);    // TODO: fix auth_tag stuff
  auth_tag_ = NULL;                                 // TODO: fix auth_tag stuff
}

u_int8_t* EncryptedPacket::getPayload()
{
  return payload_;
}






// TODO: fix auth_tag stuff

bool EncryptedPacket::hasAuthTag() const
{
//   if( auth_tag_ == NULL )
     return false;
//   return true;
}

void EncryptedPacket::withAuthTag(bool b)
{
//   if( b && (auth_tag_ != NULL) )
//     throw std::runtime_error("packet already has auth tag function enabled");
// 		//TODO: return instead?
//   if( ! b && (auth_tag_ == NULL) )
//     throw std::runtime_error("packet already has auth tag function disabled");
// 		//TODO: return instead?

//   if( b ) {
//     auth_tag_ = reinterpret_cast<AuthTag*>( buf_ + sizeof(struct HeaderStruct) );
//     payload_ = payload_ + AUTHTAG_SIZE;
//     length_ -= AUTHTAG_SIZE;
//     max_length_ -= AUTHTAG_SIZE;
//   } else {
//     payload_ = reinterpret_cast<u_int8_t*>( auth_tag_ );
//     length_ += AUTHTAG_SIZE;
//     max_length_ += AUTHTAG_SIZE;
//     auth_tag_ = NULL;
//   }
}

void EncryptedPacket::setAuthTag(AuthTag& tag)
{
//   if( auth_tag_ == NULL )
//     throw std::runtime_error("auth tag not enabled");

//   if( tag == AuthTag(0) )
//     return;

//   if( tag.getLength() != AUTHTAG_SIZE )
//     throw std::length_error("authtag length mismatch with AUTHTAG_SIZE");

//   std::memcpy( auth_tag_, tag.getBuf(), AUTHTAG_SIZE );
}

AuthTag EncryptedPacket::getAuthTag() const
{
//   if( auth_tag_ == NULL )
//     throw std::runtime_error("auth tag not enabled");

  AuthTag at(AUTHTAG_SIZE);
//  std::memcpy(at, auth_tag_, AUTHTAG_SIZE ); 
  return at;
}
