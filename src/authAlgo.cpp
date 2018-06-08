/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "authAlgo.h"
#include "log.h"
#include "anytunError.h"
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

#ifndef NO_CRYPT
//****** Sha1AuthAlgo ******

Sha1AuthAlgo::Sha1AuthAlgo(kd_dir_t d) : AuthAlgo(d), key_(DIGEST_LENGTH)
{
#if defined(USE_SSL_CRYPTO)
  ctx_ = NULL;
#elif defined(USE_NETTLE)
  // nothing here
#else  // USE_GCRYPT is the default
  handle_ = 0;
#endif
}

bool Sha1AuthAlgo::Init()
{
#if defined(USE_SSL_CRYPTO)
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if ((ctx_ = HMAC_CTX_new()) == NULL) {
    return false;
  }
# else
  if ((ctx_ = (HMAC_CTX*)calloc(1, sizeof(HMAC_CTX))) == NULL) {
    return false;
  }
  HMAC_CTX_init(ctx_);
# endif
  HMAC_Init_ex(ctx_, NULL, 0, EVP_sha1(), NULL);
#elif defined(USE_NETTLE)
  // nothing here
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_md_open(&handle_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "Sha1AuthAlgo::Sha1AuthAlgo: Failed to open message digest algo";
    return false;
  }
#endif
  return true;
}

Sha1AuthAlgo::~Sha1AuthAlgo()
{
#if defined(USE_SSL_CRYPTO)
  if(ctx_) {
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx_);
# else
    HMAC_CTX_cleanup(ctx_);
    free(ctx_);
# endif
  }
#elif defined(USE_NETTLE)
  // nothing here
#else  // USE_GCRYPT is the default
  if(handle_) {
    gcry_md_close(handle_);
  }
#endif
}

void Sha1AuthAlgo::generate(KeyDerivation& kd, EncryptedPacket& packet)
{
#if defined(USE_GCRYPT)
  if(!handle_) {
    return;
  }
#endif

  packet.addAuthTag();
  if(!packet.getAuthTagLength()) {
    return;
  }

  kd.generate(dir_, LABEL_AUTH, packet.getSeqNr(), key_);
#if defined(USE_SSL_CRYPTO)
  HMAC_Init_ex(ctx_, key_.getBuf(), key_.getLength(), EVP_sha1(), NULL);

  uint8_t hmac[DIGEST_LENGTH];
  HMAC_Update(ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  HMAC_Final(ctx_, hmac, NULL);
#elif defined(USE_NETTLE)
  hmac_sha1_set_key(&ctx_, key_.getLength(), key_.getBuf());

  uint8_t hmac[DIGEST_LENGTH];
  hmac_sha1_update(&ctx_, packet.getAuthenticatedPortionLength(), packet.getAuthenticatedPortion());
  hmac_sha1_digest(&ctx_, DIGEST_LENGTH, hmac);
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_md_setkey(handle_, key_.getBuf(), key_.getLength());
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "Sha1AuthAlgo::setKey: Failed to set hmac key: " << AnytunGpgError(err);
    return;
  }

  gcry_md_reset(handle_);
  gcry_md_write(handle_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  gcry_md_final(handle_);
  uint8_t* hmac = gcry_md_read(handle_, 0);
#endif

  uint8_t* tag = packet.getAuthTag();
  uint32_t length = (packet.getAuthTagLength() < DIGEST_LENGTH) ? packet.getAuthTagLength() : DIGEST_LENGTH;

  if(length > DIGEST_LENGTH) {
    std::memset(tag, 0, packet.getAuthTagLength());
  }

  std::memcpy(&tag[packet.getAuthTagLength() - length], &hmac[DIGEST_LENGTH - length], length);
}

bool Sha1AuthAlgo::checkTag(KeyDerivation& kd, EncryptedPacket& packet)
{
#if defined(USE_GCRYPT)
  if(!handle_) {
    return false;
  }
#endif

  packet.withAuthTag(true);
  if(!packet.getAuthTagLength()) {
    return true;
  }

  kd.generate(dir_, LABEL_AUTH, packet.getSeqNr(), key_);
#if defined(USE_SSL_CRYPTO)
  HMAC_Init_ex(ctx_, key_.getBuf(), key_.getLength(), EVP_sha1(), NULL);

  uint8_t hmac[DIGEST_LENGTH];
  HMAC_Update(ctx_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  HMAC_Final(ctx_, hmac, NULL);
#elif defined(USE_NETTLE)
  hmac_sha1_set_key(&ctx_, key_.getLength(), key_.getBuf());

  uint8_t hmac[DIGEST_LENGTH];
  hmac_sha1_update(&ctx_, packet.getAuthenticatedPortionLength(), packet.getAuthenticatedPortion());
  hmac_sha1_digest(&ctx_, DIGEST_LENGTH, hmac);
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_md_setkey(handle_, key_.getBuf(), key_.getLength());
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "Sha1AuthAlgo::setKey: Failed to set hmac key: " << AnytunGpgError(err);
    return false;
  }

  gcry_md_reset(handle_);
  gcry_md_write(handle_, packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength());
  gcry_md_final(handle_);
  uint8_t* hmac = gcry_md_read(handle_, 0);
#endif

  uint8_t* tag = packet.getAuthTag();
  uint32_t length = (packet.getAuthTagLength() < DIGEST_LENGTH) ? packet.getAuthTagLength() : DIGEST_LENGTH;

  if(length > DIGEST_LENGTH)
    for(uint32_t i=0; i < (packet.getAuthTagLength() - DIGEST_LENGTH); ++i)
      if(tag[i]) { return false; }

  int ret = std::memcmp(&tag[packet.getAuthTagLength() - length], &hmac[DIGEST_LENGTH - length], length);
  packet.removeAuthTag();

  if(ret) {
    return false;
  }

  return true;
}

#endif
