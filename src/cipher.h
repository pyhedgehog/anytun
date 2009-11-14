/**
 *  \file
 *  \brief Cipher interface and implementation definitions.
 */
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
#ifndef ANYTUN_cipher_h_INCLUDED
#define ANYTUN_cipher_h_INCLUDED

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif
#endif

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"
#include "plainPacket.h"
#include "keyDerivation.h"


/// Interface class for cipher implementations.
class Cipher {
public:
  Cipher() : dir_(KD_INBOUND) {};
  Cipher(kd_dir_t d) : dir_(d) {};
  virtual ~Cipher() {};

  // TODO could those two be const?
  void encrypt(KeyDerivation& kd, PlainPacket & in, EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  void decrypt(KeyDerivation& kd, EncryptedPacket & in, PlainPacket & out);
  
protected:
  // TODO could those two be const?
  virtual u_int32_t cipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0;
  virtual u_int32_t decipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0; 

  kd_dir_t dir_;
};


/// Test-only non-encrypting encryption.
class NullCipher : public Cipher {
protected:
  virtual u_int32_t cipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  virtual u_int32_t decipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
};


#ifndef NO_CRYPT
/// En-/Decryption based on AES Integer Counter Mode.
class AesIcmCipher : public Cipher {
public:
  AesIcmCipher(kd_dir_t d);
  AesIcmCipher(kd_dir_t d, u_int16_t key_length);
  ~AesIcmCipher();
  
  static const u_int16_t DEFAULT_KEY_LENGTH = 128;
  static const u_int16_t CTR_LENGTH = 16;
  static const u_int16_t SALT_LENGTH = 14;

protected:
  // TODO could those be const?
  virtual u_int32_t cipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  virtual u_int32_t decipher(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

private:
  void init(u_int16_t key_length = DEFAULT_KEY_LENGTH);

  void calcCtr(KeyDerivation& kd, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  void calc(KeyDerivation& kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_;
#else
  AES_KEY aes_key_;
  u_int8_t ecount_buf_[AES_BLOCK_SIZE];
#endif
  Buffer key_;
  Buffer salt_;

#ifdef _MSC_VER
  #pragma pack(push, 1)
#endif
  union ATTR_PACKED cipher_aesctr_ctr_union {
    u_int8_t buf_[CTR_LENGTH];
    struct ATTR_PACKED {
      u_int8_t buf_[SALT_LENGTH];
      u_int16_t zero_;
    } salt_;
	struct ATTR_PACKED {
      u_int8_t fill_[SALT_LENGTH - sizeof(mux_t) - sizeof(sender_id_t) - 2*sizeof(u_int8_t) - sizeof(seq_nr_t)];
      mux_t mux_;
      sender_id_t sender_id_;
      u_int8_t empty_[2];
      seq_nr_t seq_nr_;
      u_int16_t zero_;
    } params_;
  } ctr_;
#ifdef _MSC_VER
  #pragma pack(pop)
#endif
};
#endif

#endif
