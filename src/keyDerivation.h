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

#ifndef ANYTUN_keyDerivation_h_INCLUDED
#define ANYTUN_keyDerivation_h_INCLUDED

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include "syncBuffer.h"
#include "options.h"

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif
#endif
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/version.hpp>

#define LABEL_ENC 0
#define LABEL_AUTH 1
#define LABEL_SALT 2

#define LABEL_LEFT_ENC 0x356A192B
#define LABEL_RIGHT_ENC 0xDA4B9237
#define LABEL_LEFT_SALT 0x77DE68DA
#define LABEL_RIGHT_SALT 0x1B645389
#define LABEL_LEFT_AUTH 0xAC3478D6
#define LABEL_RIGHT_AUTH 0xC1DFD96E

typedef enum { KD_INBOUND, KD_OUTBOUND } kd_dir_t;

class KeyDerivation
{
public:
  KeyDerivation() : is_initialized_(false), role_(ROLE_LEFT), key_length_(0), master_salt_(0), master_key_(0) {};
  KeyDerivation(uint16_t key_length) : is_initialized_(false), role_(ROLE_LEFT), key_length_(key_length), master_salt_(0), master_key_(0) {};
  virtual ~KeyDerivation() {};

  void setRole(const role_t role);

  virtual void init(Buffer key, Buffer salt, std::string passphrase = "") = 0;
  virtual bool generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key) = 0;

  virtual std::string printType() { return "GenericKeyDerivation"; };

  satp_prf_label_t convertLabel(kd_dir_t dir, satp_prf_label_t label);

protected:
  virtual void updateMasterKey() = 0;

#ifndef NO_PASSPHRASE
  void calcMasterKey(std::string passphrase, uint16_t length);
  void calcMasterSalt(std::string passphrase, uint16_t length);
#endif

  KeyDerivation(const KeyDerivation& src);
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    WritersLock lock(mutex_);
    ar& role_;
    ar& key_length_;
    ar& master_salt_;
    ar& master_key_;
    updateMasterKey();
  }

  bool is_initialized_;
  role_t role_;
  uint16_t key_length_;
  SyncBuffer master_salt_;
  SyncBuffer master_key_;

  SharedMutex mutex_;
};

#if BOOST_VERSION <= 103500
BOOST_IS_ABSTRACT(KeyDerivation);
#else
BOOST_SERIALIZATION_ASSUME_ABSTRACT(KeyDerivation);
#endif

//****** NullKeyDerivation ******

class NullKeyDerivation : public KeyDerivation
{
public:
  NullKeyDerivation() {};
  ~NullKeyDerivation() {};

  void init(Buffer key, Buffer salt, std::string passphrase = "") {};
  bool generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key);

  std::string printType() { return "NullKeyDerivation"; };

private:
  void updateMasterKey() {};

  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    ar& boost::serialization::base_object<KeyDerivation>(*this);
  }

};

#ifndef NO_CRYPT
//****** AesIcmKeyDerivation ******

class AesIcmKeyDerivation : public KeyDerivation
{
public:
  AesIcmKeyDerivation();
  AesIcmKeyDerivation(uint16_t key_length);
  ~AesIcmKeyDerivation();

  static const uint16_t DEFAULT_KEY_LENGTH = 128;
  static const uint16_t CTR_LENGTH = 16;
  static const uint16_t SALT_LENGTH = 14;

  void init(Buffer key, Buffer salt, std::string passphrase = "");
  bool generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key);

  std::string printType();

private:
  void updateMasterKey();

  bool calcCtr(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr);

  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    ar& boost::serialization::base_object<KeyDerivation>(*this);
  }

#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_[2];
#else
  AES_KEY aes_key_[2];
  uint8_t ecount_buf_[2][AES_BLOCK_SIZE];
#endif

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
  union ATTR_PACKED key_derivation_aesctr_ctr_union {
    uint8_t buf_[CTR_LENGTH];
    struct ATTR_PACKED {
      uint8_t buf_[SALT_LENGTH];
      uint16_t zero_;
    } salt_;
    struct ATTR_PACKED {
      uint8_t fill_[SALT_LENGTH - sizeof(satp_prf_label_t) - sizeof(seq_nr_t)];
      satp_prf_label_t label_;
      seq_nr_t seq_;
      uint16_t zero_;
    } params_;
  } ctr_[2];
#ifdef _MSC_VER
#pragma pack(pop)
#endif
};

#endif

#endif
