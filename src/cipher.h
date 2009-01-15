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

#ifndef _CIPHER_H_
#define _CIPHER_H_

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"
#include "plainPacket.h"
#include "keyDerivation.h"

#ifndef NOCRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif
#endif

class Cipher
{
public:
  virtual ~Cipher() {};

	void encrypt(KeyDerivation& kd, kd_dir_t dir, PlainPacket & in, EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
	void decrypt(KeyDerivation& kd, kd_dir_t dir, EncryptedPacket & in, PlainPacket & out);
  
protected:
  virtual u_int32_t cipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0;
  virtual u_int32_t decipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0; 
};

//****** NullCipher ******

class NullCipher : public Cipher
{
protected:
  u_int32_t cipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  u_int32_t decipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
};

#ifndef NOCRYPT
//****** AesIcmCipher ******

class AesIcmCipher : public Cipher
{
public:
  AesIcmCipher();
  AesIcmCipher(u_int16_t key_length);
  ~AesIcmCipher();
  
  static const u_int16_t DEFAULT_KEY_LENGTH = 128;
  static const u_int16_t CTR_LENGTH = 16;
  static const u_int16_t SALT_LENGTH = 14;

protected:
  u_int32_t cipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  u_int32_t decipher(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

private:
  void init(u_int16_t key_length = DEFAULT_KEY_LENGTH);

  void calcCtr(KeyDerivation& kd, kd_dir_t dir, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  void calc(KeyDerivation& kd, kd_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_;
#else
  AES_KEY aes_key_;
  u_int8_t ecount_buf_[AES_BLOCK_SIZE];
#endif
  Buffer key_;
  Buffer salt_;

  union __attribute__((__packed__)) cipher_aesctr_ctr_union {
    u_int8_t buf_[CTR_LENGTH];
    struct __attribute__ ((__packed__)) {
      u_int8_t buf_[SALT_LENGTH];
      u_int16_t zero_;
    } salt_;
    struct __attribute__((__packed__)) {
      u_int8_t fill_[SALT_LENGTH - sizeof(mux_t) - sizeof(sender_id_t) - 2 - sizeof(seq_nr_t)];
      mux_t mux_;
      sender_id_t sender_id_;
      u_int8_t empty_[2];
      seq_nr_t seq_nr_;
      u_int16_t zero_;
    } params_;
  } ctr_;
};
#endif

#endif
