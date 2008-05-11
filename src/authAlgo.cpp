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

#include "authAlgo.h"
#include "log.h"
#include "buffer.h"
#include "encryptedPacket.h"

#include <iostream>

#include <gcrypt.h>

//****** NullAuthAlgo ******
void NullAuthAlgo::generate(EncryptedPacket& packet)
{
}

bool NullAuthAlgo::checkTag(EncryptedPacket& packet)
{
  return true;
}

u_int32_t NullAuthAlgo::getMaxLength()
{
  return MAX_LENGTH_;
}

//****** Sha1AuthAlgo ******

Sha1AuthAlgo::Sha1AuthAlgo() : ctx_(NULL)
{
  gcry_error_t err = gcry_md_open( &ctx_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC );
  if( err )
    cLog.msg(Log::PRIO_CRIT) << "Sha1AuthAlgo::Sha1AuthAlgo: Failed to open message digest algo";
}

Sha1AuthAlgo::~Sha1AuthAlgo()
{
  if(ctx_)
    gcry_md_close( ctx_ );
}

void Sha1AuthAlgo::setKey(Buffer& key)
{
  if(!ctx_)
    return;

  gcry_error_t err = gcry_md_setkey( ctx_, key.getBuf(), key.getLength() );
  if( err ) {
    char buf[NL_TEXTMAX];
    cLog.msg(Log::PRIO_ERR) << "Sha1AuthAlgo::setKey: Failed to set cipher key: " << gpg_strerror_r(err, buf, NL_TEXTMAX);
  }
}

void Sha1AuthAlgo::generate(EncryptedPacket& packet)
{
  if(!packet.getAuthTagLength())
    return;

  gcry_md_reset( ctx_ );

  gcry_md_write( ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength() );
  gcry_md_final( ctx_ );

  u_int8_t* tag = packet.getAuthTag();
  if(packet.getAuthTagLength() > MAX_LENGTH_)
    std::memset(tag, 0, (packet.getAuthTagLength() - MAX_LENGTH_));
  
  u_int8_t* hmac = gcry_md_read(ctx_, 0);
  u_int32_t length = (packet.getAuthTagLength() < MAX_LENGTH_) ? packet.getAuthTagLength() : MAX_LENGTH_;
  std::memcpy(&tag[packet.getAuthTagLength() - length], &hmac[MAX_LENGTH_ - length], length);
}

bool Sha1AuthAlgo::checkTag(EncryptedPacket& packet)
{
  if(!packet.getAuthTagLength())
    return true;

  gcry_md_reset( ctx_ );

  gcry_md_write( ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength() );
  gcry_md_final( ctx_ );

  u_int8_t* tag = packet.getAuthTag();
  if(packet.getAuthTagLength() > MAX_LENGTH_)
    for(u_int32_t i=0; i < (packet.getAuthTagLength() - MAX_LENGTH_); ++i)
      if(tag[i]) return false; 
  
  u_int8_t* hmac = gcry_md_read(ctx_, 0);
  u_int32_t length = (packet.getAuthTagLength() < MAX_LENGTH_) ? packet.getAuthTagLength() : MAX_LENGTH_;
  if(std::memcmp(&tag[packet.getAuthTagLength() - length], &hmac[MAX_LENGTH_ - length], length))
    return false;

  return true;
}

u_int32_t Sha1AuthAlgo::getMaxLength()
{
  return MAX_LENGTH_;
}
