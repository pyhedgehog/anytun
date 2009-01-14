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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "authAlgo.h"
#include "log.h"
#include "buffer.h"
#include "encryptedPacket.h"

#include <iostream>
#include <cstring>

//****** NullAuthAlgo ******
void NullAuthAlgo::generate(KeyDerivation& kd, EncryptedPacket& packet)
{
}

bool NullAuthAlgo::checkTag(KeyDerivation& kd, EncryptedPacket& packet)
{
  return true;
}

#ifndef NOCRYPT
//****** Sha1AuthAlgo ******

Sha1AuthAlgo::Sha1AuthAlgo() : key_(DIGEST_LENGTH)
{
#ifndef USE_SSL_CRYPTO
  gcry_error_t err = gcry_md_open(&handle_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if(err) {
    cLog.msg(Log::PRIO_CRIT) << "Sha1AuthAlgo::Sha1AuthAlgo: Failed to open message digest algo";
    return;
  } 
#else
  HMAC_CTX_init(&ctx_);
  HMAC_Init_ex(&ctx_, NULL, 0, EVP_sha1(), NULL);
#endif
}

Sha1AuthAlgo::~Sha1AuthAlgo()
{
#ifndef USE_SSL_CRYPTO
  if(handle_)
    gcry_md_close(handle_);
#else
  HMAC_CTX_cleanup(&ctx_);
#endif    
}

void Sha1AuthAlgo::generate(KeyDerivation& kd, EncryptedPacket& packet)
{
  packet.addAuthTag();
  if(!packet.getAuthTagLength())
    return;
  
  bool result = kd.generate(LABEL_SATP_MSG_AUTH, packet.getSeqNr(), key_);
  if(result) { // a new key got generated
#ifndef USE_SSL_CRYPTO
    gcry_error_t err = gcry_md_setkey(handle_, key_.getBuf(), key_.getLength());
    if(err) {
      char buf[STERROR_TEXT_MAX];
      buf[0] = 0;
      cLog.msg(Log::PRIO_ERR) << "Sha1AuthAlgo::setKey: Failed to set hmac key: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
      return;
    } 
#else 
    HMAC_Init_ex(&ctx_, key_.getBuf(), key_.getLength(), EVP_sha1(), NULL);
  }
  else {
    HMAC_Init_ex(&ctx_, NULL, 0, NULL, NULL);
#endif
  }

#ifndef USE_SSL_CRYPTO
  gcry_md_reset(handle_);
  gcry_md_write(handle_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  gcry_md_final(handle_);
  u_int8_t* hmac = gcry_md_read(handle_, 0);
#else
  u_int8_t hmac[DIGEST_LENGTH];
  HMAC_Update(&ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  HMAC_Final(&ctx_, hmac, NULL);
#endif

  u_int8_t* tag = packet.getAuthTag();
  u_int32_t length = (packet.getAuthTagLength() < DIGEST_LENGTH) ? packet.getAuthTagLength() : DIGEST_LENGTH;

  if(length > DIGEST_LENGTH)
    std::memset(tag, 0, packet.getAuthTagLength());

  std::memcpy(&tag[packet.getAuthTagLength() - length], &hmac[DIGEST_LENGTH - length], length);
}

bool Sha1AuthAlgo::checkTag(KeyDerivation& kd, EncryptedPacket& packet)
{
  packet.withAuthTag(true);
  if(!packet.getAuthTagLength())
    return true;

  bool result = kd.generate(LABEL_SATP_MSG_AUTH, packet.getSeqNr(), key_);
  if(result) { // a new key got generated
#ifndef USE_SSL_CRYPTO
    gcry_error_t err = gcry_md_setkey(handle_, key_.getBuf(), key_.getLength());
    if(err) {
      char buf[STERROR_TEXT_MAX];
      buf[0] = 0;
      cLog.msg(Log::PRIO_ERR) << "Sha1AuthAlgo::setKey: Failed to set hmac key: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
      return false;
    } 
#else 
    HMAC_Init_ex(&ctx_, key_.getBuf(), key_.getLength(), EVP_sha1(), NULL);
  }
  else {
    HMAC_Init_ex(&ctx_, NULL, 0, NULL, NULL);
#endif
  }

#ifndef USE_SSL_CRYPTO
  gcry_md_reset(handle_);
  gcry_md_write(handle_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  gcry_md_final(handle_);
  u_int8_t* hmac = gcry_md_read(handle_, 0);
#else
  u_int8_t hmac[DIGEST_LENGTH];
  HMAC_Update(&ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  HMAC_Final(&ctx_, hmac, NULL);
#endif

  u_int8_t* tag = packet.getAuthTag();
  u_int32_t length = (packet.getAuthTagLength() < DIGEST_LENGTH) ? packet.getAuthTagLength() : DIGEST_LENGTH;

  if(length > DIGEST_LENGTH)
    for(u_int32_t i=0; i < (packet.getAuthTagLength() - DIGEST_LENGTH); ++i)
      if(tag[i]) return false;

  int ret = std::memcmp(&tag[packet.getAuthTagLength() - length], &hmac[DIGEST_LENGTH - length], length);
  packet.removeAuthTag();
  
  if(ret)
    return false;

  return true;

}

#endif

