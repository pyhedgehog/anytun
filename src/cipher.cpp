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

#include <stdexcept>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstring>

#include "endian.h"

#include "cipher.h"
#if defined(USE_NETTLE)
#include <nettle/ctr.h>
#endif

#include "log.h"
#include "anytunError.h"

void Cipher::encrypt(KeyDerivation& kd, PlainPacket& in, EncryptedPacket& out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  uint32_t len = cipher(kd, in, in.getLength(), out.getPayload(), out.getPayloadLength(), seq_nr, sender_id, mux);
  out.setSenderId(sender_id);
  out.setSeqNr(seq_nr);
  out.setMux(mux);
  out.setPayloadLength(len);
}

void Cipher::decrypt(KeyDerivation& kd, EncryptedPacket& in, PlainPacket& out)
{
  uint32_t len = decipher(kd, in.getPayload() , in.getPayloadLength(), out, out.getLength(), in.getSeqNr(), in.getSenderId(), in.getMux());
  out.setLength(len);
}


//******* NullCipher *******

uint32_t NullCipher::cipher(KeyDerivation& kd, uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

uint32_t NullCipher::decipher(KeyDerivation& kd, uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

#ifndef NO_CRYPT
//****** AesIcmCipher ******

AesIcmCipher::AesIcmCipher(kd_dir_t d) : Cipher(d), key_(uint32_t(DEFAULT_KEY_LENGTH/8)), salt_(uint32_t(SALT_LENGTH))
{
  init();
}

AesIcmCipher::AesIcmCipher(kd_dir_t d, uint16_t key_length) : Cipher(d), key_(uint32_t(key_length/8)), salt_(uint32_t(SALT_LENGTH))
{
  init(key_length);
}

void AesIcmCipher::init(uint16_t key_length)
{
#if defined(USE_SSL_CRYPTO)
    // nothing here
#elif defined(USE_NETTLE)
    // nothing here
#else  // USE_GCRYPT is the default
  handle_ = NULL;
  int algo;
  switch(key_length) {
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
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher::AesIcmCipher: cipher key length of " << key_length << " Bits is not supported";
    return;
  }
  }

  gcry_error_t err = gcry_cipher_open(&handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher::AesIcmCipher: Failed to open cipher" << AnytunGpgError(err);
  }
#endif
}


AesIcmCipher::~AesIcmCipher()
{
#if defined(USE_SSL_CRYPTO)
    // nothing here
#elif defined(USE_NETTLE)
    // nothing here
#else  // USE_GCRYPT is the default
  if(handle_) {
    gcry_cipher_close(handle_);
  }
#endif
}

uint32_t AesIcmCipher::cipher(KeyDerivation& kd, uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  calc(kd, in, ilen, out, olen, seq_nr, sender_id, mux);
  return (ilen < olen) ? ilen : olen;
}

uint32_t AesIcmCipher::decipher(KeyDerivation& kd, uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  calc(kd, in, ilen, out, olen, seq_nr, sender_id, mux);
  return (ilen < olen) ? ilen : olen;
}

void AesIcmCipher::calcCtr(KeyDerivation& kd, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  kd.generate(dir_, LABEL_SALT, seq_nr, salt_);

  std::memcpy(ctr_.salt_.buf_, salt_.getBuf(), SALT_LENGTH);
  ctr_.salt_.zero_ = 0;
  ctr_.params_.mux_ ^= MUX_T_HTON(mux);
  ctr_.params_.sender_id_ ^= SENDER_ID_T_HTON(sender_id);
  ctr_.params_.seq_nr_ ^= SEQ_NR_T_HTON(seq_nr);

  return;
}

void AesIcmCipher::calc(KeyDerivation& kd, uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
#if defined(USE_GCRYPT)
  if(!handle_) {
    return;
  }
#endif

  kd.generate(dir_, LABEL_ENC, seq_nr, key_);
#if defined(USE_SSL_CRYPTO)
  int ret = AES_set_encrypt_key(key_.getBuf(), key_.getLength()*8, &aes_key_);
  if(ret) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher ssl key (code: " << ret << ")";
    return;
  }
#elif defined(USE_NETTLE)
  aes_set_encrypt_key(&ctx_, key_.getLength(), key_.getBuf());
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_cipher_setkey(handle_, key_.getBuf(), key_.getLength());
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher key: " << AnytunGpgError(err);
    return;
  }
#endif

  calcCtr(kd, seq_nr, sender_id, mux);

#if defined(USE_SSL_CRYPTO)
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    return;
  }
  unsigned int num = 0;
  std::memset(ecount_buf_, 0, AES_BLOCK_SIZE);
  CRYPTO_ctr128_encrypt(in, out, (ilen < olen) ? ilen : olen, &aes_key_, ctr_.buf_, ecount_buf_, &num, (block128_f)AES_encrypt);
#elif defined(USE_NETTLE)
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    return;
  }
  ctr_crypt(&ctx_, (nettle_crypt_func *)(aes_encrypt), AES_BLOCK_SIZE, ctr_.buf_, (ilen < olen) ? ilen : olen, out, in);
#else  // USE_GCRYPT is the default
  err = gcry_cipher_setctr(handle_, ctr_.buf_, CTR_LENGTH);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: " << AnytunGpgError(err);
    return;
  }

  err = gcry_cipher_encrypt(handle_, out, olen, in, ilen);
  if(err) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to de/encrypt packet: " << AnytunGpgError(err);
    return;
  }
#endif
}
#endif

