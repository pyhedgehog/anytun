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


#include "log.h"
#include "keyDerivation.h"
#include "threadUtils.hpp"
#include "datatypes.h"
#include "endian.h"

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <string>

void KeyDerivation::setLogKDRate(const int8_t log_rate)
{
  WritersLock lock(mutex_);
  ld_kdr_ = log_rate;
  if(ld_kdr_ > (int8_t)(sizeof(seq_nr_t) * 8))
    ld_kdr_ = sizeof(seq_nr_t) * 8;
}

//****** NullKeyDerivation ******

bool NullKeyDerivation::generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key)
{
  std::memset(key.getBuf(), 0, key.getLength());
  return true;
}

#ifndef NOCRYPT
//****** AesIcmKeyDerivation ******

AesIcmKeyDerivation::AesIcmKeyDerivation() : KeyDerivation(DEFAULT_KEY_LENGTH) 
{
#ifndef USE_SSL_CRYPTO
  for(int i=0; i<2; i++)
    handle_[i] = NULL;
#endif
}

AesIcmKeyDerivation::AesIcmKeyDerivation(u_int16_t key_length) : KeyDerivation(key_length) 
{
#ifndef USE_SSL_CRYPTO
  for(int i=0; i<2; i++)
    handle_[i] = NULL;
#endif
}

AesIcmKeyDerivation::~AesIcmKeyDerivation()
{
  WritersLock lock(mutex_);
#ifndef USE_SSL_CRYPTO
  for(int i=0; i<2; i++)
    if(handle_[i])
      gcry_cipher_close(handle_[i]);
#endif
}

void AesIcmKeyDerivation::init(Buffer key, Buffer salt)
{
  WritersLock lock(mutex_);

  master_salt_ = SyncBuffer(salt);
  master_key_ = SyncBuffer(key);

  updateMasterKey();
}

void AesIcmKeyDerivation::updateMasterKey()
{
  if(master_key_.getLength()*8 != key_length_) {
    cLog.msg(Log::PRIO_CRIT) << "KeyDerivation::updateMasterKey: key lengths don't match";
    return;
  }

  if(master_salt_.getLength() != SALT_LENGTH) {
    cLog.msg(Log::PRIO_CRIT) << "KeyDerivation::updateMasterKey: salt lengths don't match";
    return;
  }

#ifndef USE_SSL_CRYPTO
  int algo;
  switch(key_length_) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    cLog.msg(Log::PRIO_CRIT) << "KeyDerivation::updateMasterKey: cipher key length of " << key_length_ << " Bits is not supported";
    return;
  }
  }

  for(int i=0; i<2; i++) {
    if(handle_[i])
      gcry_cipher_close(handle_[i]);
    
    gcry_error_t err = gcry_cipher_open(&handle_[i], algo, GCRY_CIPHER_MODE_CTR, 0);
    if(err) {
      cLog.msg(Log::PRIO_ERR) << "KeyDerivation::updateMasterKey: Failed to open cipher: " << LogGpgError(err);
      return;
    } 
    
    err = gcry_cipher_setkey(handle_[i], master_key_.getBuf(), master_key_.getLength());
    if(err) {
      cLog.msg(Log::PRIO_ERR) << "KeyDerivation::updateMasterKey: Failed to set cipher key: " << LogGpgError(err);
      return;
    }
  }
#else
  for(int i=0; i<2; i++) {
    int ret = AES_set_encrypt_key(master_key_.getBuf(), master_key_.getLength()*8, &aes_key_[i]);
    if(ret) {
      cLog.msg(Log::PRIO_ERR) << "KeyDerivation::updateMasterKey: Failed to set ssl key (code: " << ret << ")";
      return;
    }
  }
#endif
}

std::string AesIcmKeyDerivation::printType() 
{
  ReadersLock lock(mutex_);

  std::stringstream sstr;
  sstr << "AesIcm" << key_length_ << "KeyDerivation";
  return sstr.str();
}

bool AesIcmKeyDerivation::calcCtr(kd_dir_t dir, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr)
{
  *r = 0;
  if(ld_kdr_ >= 0)
    *r = seq_nr >> ld_kdr_;

  if(key_store_[dir][label].key_.getLength() && key_store_[dir][label].r_ == *r) {
    if(!(*r) || (seq_nr % (*r)))
      return false;
  }

  if(master_salt_.getLength() != SALT_LENGTH) {
    cLog.msg(Log::PRIO_CRIT) << "KeyDerivation::calcCtr: salt lengths don't match";
    return false;
  }
  memcpy(ctr_[dir].salt_.buf_, master_salt_.getBuf(), SALT_LENGTH);
  ctr_[dir].salt_.zero_ = 0;
  ctr_[dir].params_.label_ ^= label;
  ctr_[dir].params_.r_ ^= SEQ_NR_T_HTON(*r);

  return true;
}

bool AesIcmKeyDerivation::generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key) 
{
  ReadersLock lock(mutex_);

#ifndef USE_SSL_CRYPTO
  if(!handle_[dir])
    return false;
#endif

  seq_nr_t r;
  calcCtr(dir, &r, label, seq_nr);
  bool result = calcCtr(dir, &r, label, seq_nr);
  if(!result) {
    u_int32_t len = key.getLength();
    if(len > key_store_[dir][label].key_.getLength()) {
      cLog.msg(Log::PRIO_WARNING) << "KeyDerivation::generate: stored (old) key for label " << label << " is too short, filling with zeros";
      std::memset(key.getBuf(), 0, len);
      len = key_store_[dir][label].key_.getLength();
    }
    std::memcpy(key.getBuf(), key_store_[dir][label].key_.getBuf(), len);
    return false;
  }
  
#ifndef USE_SSL_CRYPTO
  gcry_error_t err = gcry_cipher_reset(handle_[dir]);
  if(err) {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to reset cipher: " << LogGpgError(err);
  }

  err = gcry_cipher_setctr(handle_[dir], ctr_[dir].buf_, CTR_LENGTH);
  if(err) {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to set CTR: " << LogGpgError(err);
    return false;
  }

  std::memset(key.getBuf(), 0, key.getLength());
  err = gcry_cipher_encrypt(handle_[dir], key, key.getLength(), NULL, 0);
  if(err) {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to generate cipher bitstream: " << LogGpgError(err);
  }
  return true;
#else
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher CTR: size don't fits";
    return false;
  }
  u_int32_t num = 0;
  std::memset(ecount_buf_[dir], 0, AES_BLOCK_SIZE);
  std::memset(key.getBuf(), 0, key.getLength());
  AES_ctr128_encrypt(key.getBuf(), key.getBuf(), key.getLength(), &aes_key_[dir], ctr_[dir].buf_, ecount_buf_[dir], &num);
#endif
  
  if(!ld_kdr_)
    return true;

  if(key_store_[dir][label].key_.getLength() < key.getLength()) {
    key_store_[dir][label].key_.setLength(key.getLength());
  }

  std::memcpy(key_store_[dir][label].key_.getBuf(), key.getBuf(), key.getLength());
  key_store_[dir][label].r_ = r;

  return true;
}
#endif

