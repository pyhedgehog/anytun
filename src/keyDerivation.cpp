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


#include "log.h"
#include "anytunError.h"
#include "keyDerivation.h"
#include "threadUtils.hpp"
#include "datatypes.h"
#include "endian.h"

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>

#ifndef NO_CRYPT
#ifndef NO_PASSPHRASE

#if defined(USE_SSL_CRYPTO)
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/modes.h>
#elif defined(USE_NETTLE)
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/ctr.h>
#endif

#endif
#endif

void KeyDerivation::setRole(const role_t role)
{
  WritersLock lock(mutex_);
  role_ = role;
  cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation: using role " << role_;
}

#ifndef NO_CRYPT
#ifndef NO_PASSPHRASE
void KeyDerivation::calcMasterKey(std::string passphrase, uint16_t length)
{
  cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation: calculating master key from passphrase";
  if(!length) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: bad master key length";
    return;
  }

#if defined(USE_SSL_CRYPTO)
  if(length > SHA256_DIGEST_LENGTH) {
#elif defined(USE_NETTLE)
  if(length > SHA256_DIGEST_SIZE) {
#else  // USE_GCRYPT is the default
  if(length > gcry_md_get_algo_dlen(GCRY_MD_SHA256)) {
#endif
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: master key too long for passphrase algorithm";
    return;
  }

#if defined(USE_SSL_CRYPTO)
  Buffer digest(uint32_t(SHA256_DIGEST_LENGTH));
  SHA256(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.length(), digest.getBuf());
#elif defined(USE_NETTLE)
  Buffer digest(uint32_t(SHA256_DIGEST_SIZE));
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, passphrase.length(), reinterpret_cast<const unsigned char*>(passphrase.c_str()));
  sha256_digest(&ctx, digest.getLength(), digest.getBuf());
#else  // USE_GCRYPT is the default
  Buffer digest(static_cast<uint32_t>(gcry_md_get_algo_dlen(GCRY_MD_SHA256)));
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest.getBuf(), passphrase.c_str(), passphrase.length());
#endif
  master_key_.setLength(length);

  std::memcpy(master_key_.getBuf(), &digest.getBuf()[digest.getLength() - master_key_.getLength()], master_key_.getLength());
}

void KeyDerivation::calcMasterSalt(std::string passphrase, uint16_t length)
{
  cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation: calculating master salt from passphrase";
  if(!length) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: bad master salt length";
    return;
  }

#if defined(USE_SSL_CRYPTO)
  if(length > SHA_DIGEST_LENGTH) {
#elif defined(USE_NETTLE)
  if(length > SHA1_DIGEST_SIZE) {
#else  // USE_GCRYPT is the default
  if(length > gcry_md_get_algo_dlen(GCRY_MD_SHA1)) {
#endif
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: master key too long for passphrase algorithm";
    return;
  }

#if defined(USE_SSL_CRYPTO)
  Buffer digest(uint32_t(SHA_DIGEST_LENGTH));
  SHA1(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.length(), digest.getBuf());
#elif defined(USE_NETTLE)
  Buffer digest(uint32_t(SHA1_DIGEST_SIZE));
  struct sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, passphrase.length(), reinterpret_cast<const unsigned char*>(passphrase.c_str()));
  sha1_digest(&ctx, digest.getLength(), digest.getBuf());
#else  // USE_GCRYPT is the default
  Buffer digest(static_cast<uint32_t>(gcry_md_get_algo_dlen(GCRY_MD_SHA1)));
  gcry_md_hash_buffer(GCRY_MD_SHA1, digest.getBuf(), passphrase.c_str(), passphrase.length());
#endif
  master_salt_.setLength(length);

  std::memcpy(master_salt_.getBuf(), &digest.getBuf()[digest.getLength() - master_salt_.getLength()], master_salt_.getLength());
}
#endif
#endif

satp_prf_label_t KeyDerivation::convertLabel(kd_dir_t dir, satp_prf_label_t label)
{
  switch(label) {
  case LABEL_ENC: {
    if(dir == KD_OUTBOUND) {
      if(role_ == ROLE_LEFT) { return LABEL_LEFT_ENC; }
      if(role_ == ROLE_RIGHT) { return LABEL_RIGHT_ENC; }
    } else {
      if(role_ == ROLE_LEFT) { return LABEL_RIGHT_ENC; }
      if(role_ == ROLE_RIGHT) { return LABEL_LEFT_ENC; }
    }
    break;
  }
  case LABEL_SALT: {
    if(dir == KD_OUTBOUND) {
      if(role_ == ROLE_LEFT) { return LABEL_LEFT_SALT; }
      if(role_ == ROLE_RIGHT) { return LABEL_RIGHT_SALT; }
    } else {
      if(role_ == ROLE_LEFT) { return LABEL_RIGHT_SALT; }
      if(role_ == ROLE_RIGHT) { return LABEL_LEFT_SALT; }
    }
    break;
  }
  case LABEL_AUTH: {
    if(dir == KD_OUTBOUND) {
      if(role_ == ROLE_LEFT) { return LABEL_LEFT_AUTH; }
      if(role_ == ROLE_RIGHT) { return LABEL_RIGHT_AUTH; }
    } else {
      if(role_ == ROLE_LEFT) { return LABEL_RIGHT_AUTH; }
      if(role_ == ROLE_RIGHT) { return LABEL_LEFT_AUTH; }
    }
    break;
  }
  }

  return label;
}

//****** NullKeyDerivation ******

bool NullKeyDerivation::generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key)
{
  std::memset(key.getBuf(), 0, key.getLength());
  return true;
}

#ifndef NO_CRYPT
//****** AesIcmKeyDerivation ******

AesIcmKeyDerivation::AesIcmKeyDerivation() : KeyDerivation(DEFAULT_KEY_LENGTH)
{
#if defined(USE_GCRYPT)
  for(int i=0; i<2; i++) {
    handle_[i] = NULL;
  }
#endif
}

AesIcmKeyDerivation::AesIcmKeyDerivation(uint16_t key_length) : KeyDerivation(key_length)
{
#if defined(USE_GCRYPT)
  for(int i=0; i<2; i++) {
    handle_[i] = NULL;
  }
#endif
}

AesIcmKeyDerivation::~AesIcmKeyDerivation()
{
  WritersLock lock(mutex_);
#if defined(USE_GCRYPT)
  for(int i=0; i<2; i++)
    if(handle_[i]) {
      gcry_cipher_close(handle_[i]);
    }
#endif
}

void AesIcmKeyDerivation::init(Buffer key, Buffer salt, std::string passphrase)
{
  WritersLock lock(mutex_);

  is_initialized_ = false;
#ifndef NO_PASSPHRASE
  if(passphrase != "" && !key.getLength()) {
    calcMasterKey(passphrase, key_length_/8);
  } else {
    master_key_ = SyncBuffer(key);
  }

  if(passphrase != "" && !salt.getLength()) {
    calcMasterSalt(passphrase, SALT_LENGTH);
  } else {
    master_salt_ = SyncBuffer(salt);
  }
#else
  master_key_ = SyncBuffer(key);
  master_salt_ = SyncBuffer(salt);
#endif

  updateMasterKey();
}

void AesIcmKeyDerivation::updateMasterKey()
{
  if(master_key_.getLength()*8 != key_length_) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: key lengths don't match";
    return;
  }

  if(master_salt_.getLength() != SALT_LENGTH) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: salt lengths don't match";
    return;
  }

#if defined(USE_SSL_CRYPTO)
  for(int i=0; i<2; i++) {
    int ret = AES_set_encrypt_key(master_key_.getBuf(), master_key_.getLength()*8, &aes_key_[i]);
    if(ret) {
      cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: Failed to set ssl key (code: " << ret << ")";
      return;
    }
  }
#elif defined(USE_NETTLE)
  for(int i=0; i<2; i++) {
    aes_set_encrypt_key(&(ctx_[i]), master_key_.getLength(), master_key_.getBuf());
  }
#else  // USE_GCRYPT is the default
  int algo;
  switch(key_length_) {
  case 128:
    algo = GCRY_CIPHER_AES128;
    break;
  case 192:
    algo = GCRY_CIPHER_AES192;
    break;
  case 256:
    algo = GCRY_CIPHER_AES256;
    break;
  default: {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: cipher key length of " << key_length_ << " Bits is not supported";
    return;
  }
  }

  for(int i=0; i<2; i++) {
    if(handle_[i]) {
      gcry_cipher_close(handle_[i]);
    }

    gcry_error_t err = gcry_cipher_open(&handle_[i], algo, GCRY_CIPHER_MODE_CTR, 0);
    if(err) {
      cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: Failed to open cipher: " << AnytunGpgError(err);
      return;
    }

    err = gcry_cipher_setkey(handle_[i], master_key_.getBuf(), master_key_.getLength());
    if(err) {
      cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::updateMasterKey: Failed to set cipher key: " << AnytunGpgError(err);
      return;
    }
  }
#endif
  is_initialized_ = true;
}

std::string AesIcmKeyDerivation::printType()
{
  ReadersLock lock(mutex_);

  std::stringstream sstr;
  sstr << "AesIcm" << key_length_ << "KeyDerivation";
  return sstr.str();
}

bool AesIcmKeyDerivation::calcCtr(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr)
{
  if(master_salt_.getLength() != SALT_LENGTH) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::calcCtr: salt lengths don't match";
    return false;
  }
  std::memcpy(ctr_[dir].salt_.buf_, master_salt_.getBuf(), SALT_LENGTH);
  ctr_[dir].salt_.zero_ = 0;
  ctr_[dir].params_.label_ ^= SATP_PRF_LABEL_T_HTON(convertLabel(dir, label));
  ctr_[dir].params_.seq_ ^= SEQ_NR_T_HTON(seq_nr);

  return true;
}

bool AesIcmKeyDerivation::generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key)
{
  ReadersLock lock(mutex_);

  if(!is_initialized_) {
    return false;
  }

  if(!calcCtr(dir, label, seq_nr)) {
    return false;
  }

#if defined(USE_SSL_CRYPTO)
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    return false;
  }
  unsigned int num = 0;
  std::memset(key.getBuf(), 0, key.getLength());
  std::memset(ecount_buf_[dir], 0, AES_BLOCK_SIZE);
  CRYPTO_ctr128_encrypt(key.getBuf(), key.getBuf(), key.getLength(), &aes_key_[dir], ctr_[dir].buf_, ecount_buf_[dir], &num, (block128_f)AES_encrypt);
#elif defined(USE_NETTLE)
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    return false;
  }
  std::memset(key.getBuf(), 0, key.getLength());
  ctr_crypt(&(ctx_[dir]), (nettle_crypt_func *)(aes_encrypt), AES_BLOCK_SIZE, ctr_[dir].buf_, key.getLength(), key.getBuf(), key.getBuf());
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_cipher_reset(handle_[dir]);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::generate: Failed to reset cipher: " << AnytunGpgError(err);
  }

  err = gcry_cipher_setctr(handle_[dir], ctr_[dir].buf_, CTR_LENGTH);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::generate: Failed to set CTR: " << AnytunGpgError(err);
    return false;
  }

  std::memset(key.getBuf(), 0, key.getLength());
  err = gcry_cipher_encrypt(handle_[dir], key, key.getLength(), NULL, 0);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation::generate: Failed to generate cipher bitstream: " << AnytunGpgError(err);
  }
#endif

  return true;
}
#endif

