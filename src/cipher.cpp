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

#include <stdexcept>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstring>

#include "endian.h"

#include "cipher.h"
#include "log.h"

void Cipher::encrypt(KeyDerivation& kd, kd_dir_t dir, PlainPacket & in, EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
	u_int32_t len = cipher(kd, dir, in, in.getLength(), out.getPayload(), out.getPayloadLength(), seq_nr, sender_id, mux);
	out.setSenderId(sender_id);
	out.setSeqNr(seq_nr);
  out.setMux(mux);
	out.setPayloadLength(len);
}

void Cipher::decrypt(KeyDerivation& kd, kd_dir_t dir, EncryptedPacket & in, PlainPacket & out)
{
	u_int32_t len = decipher(kd, dir, in.getPayload() , in.getPayloadLength(), out, out.getLength(), in.getSeqNr(), in.getSenderId(), in.getMux());
	out.setLength(len);
}


//******* NullCipher *******

u_int32_t NullCipher::cipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
	std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

u_int32_t NullCipher::decipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
	std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

#ifndef NOCRYPT
//****** AesIcmCipher ****** 

AesIcmCipher::AesIcmCipher() : key_(u_int32_t(DEFAULT_KEY_LENGTH/8)), salt_(u_int32_t(SALT_LENGTH))
{
  init();
}

AesIcmCipher::AesIcmCipher(u_int16_t key_length) : key_(u_int32_t(key_length/8)), salt_(u_int32_t(SALT_LENGTH))
{
  init(key_length);
}

void AesIcmCipher::init(u_int16_t key_length)
{
#ifndef USE_SSL_CRYPTO
  handle_ = NULL;
  int algo;
  switch(key_length) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_CRIT) << "AesIcmCipher::AesIcmCipher: cipher key length of " << key_length << " Bits is not supported";
    return;
  }
  }

  gcry_error_t err = gcry_cipher_open(&handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if( err ) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_CRIT) << "AesIcmCipher::AesIcmCipher: Failed to open cipher" << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
  } 
#endif
}


AesIcmCipher::~AesIcmCipher()
{
#ifndef USE_SSL_CRYPTO
  if(handle_)
    gcry_cipher_close(handle_);
#endif
}

u_int32_t AesIcmCipher::cipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  calc(kd, dir, in, ilen, out, olen, seq_nr, sender_id, mux);
  return (ilen < olen) ? ilen : olen;
}

u_int32_t AesIcmCipher::decipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  calc(kd, dir, in, ilen, out, olen, seq_nr, sender_id, mux);
  return (ilen < olen) ? ilen : olen;
}

void AesIcmCipher::calcCtr(KeyDerivation& kd, kd_dir_t dir, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  kd.generate(dir, LABEL_SATP_SALT, seq_nr, salt_);

#ifdef ANYTUN_02_COMPAT
  if(!salt_[int32_t(0)])
    salt_[int32_t(0)] = 1;
#endif

  std::memcpy(ctr_.salt_.buf_, salt_.getBuf(), SALT_LENGTH);
  ctr_.salt_.zero_ = 0;
  ctr_.params_.mux_ ^= MUX_T_HTON(mux);
  ctr_.params_.sender_id_ ^= SENDER_ID_T_HTON(sender_id);
  ctr_.params_.seq_nr_ ^= SEQ_NR_T_HTON(seq_nr);

  return;
}

void AesIcmCipher::calc(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
#ifndef USE_SSL_CRYPTO
  if(!handle_)
    return;
#endif

  kd.generate(dir, LABEL_SATP_ENCRYPTION, seq_nr, key_);
#ifdef USE_SSL_CRYPTO
  int ret = AES_set_encrypt_key(key_.getBuf(), key_.getLength()*8, &aes_key_);
  if(ret) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher ssl key (code: " << ret << ")";
    return;
  }
#else
  gcry_error_t err = gcry_cipher_setkey(handle_, key_.getBuf(), key_.getLength());
  if(err) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher key: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
    return;
  }
#endif

  calcCtr(kd, dir, seq_nr, sender_id, mux);
 
#ifndef USE_SSL_CRYPTO
  err = gcry_cipher_setctr(handle_, ctr_.buf_, CTR_LENGTH);
  if(err) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher CTR: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
    return;
  }

  err = gcry_cipher_encrypt(handle_, out, olen, in, ilen);
  if(err) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to de/encrypt packet: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX);
    return;
  }
#else
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher CTR: size don't fits";
    return;
  }
  u_int32_t num = 0;
  std::memset(ecount_buf_, 0, AES_BLOCK_SIZE);
  AES_ctr128_encrypt(in, out, (ilen < olen) ? ilen : olen, &aes_key_, ctr_.buf_, ecount_buf_, &num);
#endif
}
#endif

