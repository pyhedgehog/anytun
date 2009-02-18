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

#ifndef _KEYDERIVATION_H_
#define _KEYDERIVATION_H_

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include "syncBuffer.h"

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif
#endif
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#define KD_LABEL_COUNT 3
typedef enum {
  LABEL_SATP_ENCRYPTION  = 0x00,
  LABEL_SATP_MSG_AUTH    = 0x01,
  LABEL_SATP_SALT        = 0x02,
} satp_prf_label_t;

typedef enum {
  KD_INBOUND = 0,
  KD_OUTBOUND = 1
} kd_dir_t;

typedef struct {
  Buffer key_;
  seq_nr_t r_;
} key_store_t;

class KeyDerivation
{
public:
  KeyDerivation() : is_initialized_(false), ld_kdr_(0), anytun02_compat_(false), key_length_(0), master_salt_(0), master_key_(0) {};
  KeyDerivation(bool a) : is_initialized_(false), ld_kdr_(0), anytun02_compat_(a), key_length_(0), master_salt_(0), master_key_(0) {};
  KeyDerivation(u_int16_t key_length) : is_initialized_(false), ld_kdr_(0), anytun02_compat_(false), key_length_(key_length), master_salt_(0), master_key_(0) {};
  KeyDerivation(bool a, u_int16_t key_length) : is_initialized_(false), ld_kdr_(0), anytun02_compat_(a), key_length_(key_length), master_salt_(0), master_key_(0) {};
  virtual ~KeyDerivation() {};

  void setLogKDRate(const int8_t ld_rate);

  virtual void init(Buffer key, Buffer salt, std::string passphrase = "") = 0;
  virtual bool generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key) = 0;

  virtual std::string printType() { return "GenericKeyDerivation"; };

protected:
  virtual void updateMasterKey() = 0;
  
#ifndef NO_PASSPHRASE
  void calcMasterKey(std::string passphrase, u_int16_t length);
  void calcMasterSalt(std::string passphrase, u_int16_t length);
#endif

	KeyDerivation(const KeyDerivation & src);
	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
 		WritersLock lock(mutex_);
    ar & ld_kdr_;
    ar & key_length_;
    ar & master_salt_;
    ar & master_key_;
    updateMasterKey();
	}

  bool is_initialized_;
  int8_t ld_kdr_;             // ld(key_derivation_rate)
  bool anytun02_compat_;
  u_int16_t key_length_;
  SyncBuffer master_salt_;
  SyncBuffer master_key_;

  SharedMutex mutex_;
};

BOOST_IS_ABSTRACT(KeyDerivation)

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
	void serialize(Archive & ar, const unsigned int version)
	{
    ar & boost::serialization::base_object<KeyDerivation>(*this);
	}

};

#ifndef NO_CRYPT
//****** AesIcmKeyDerivation ******

class AesIcmKeyDerivation : public KeyDerivation
{
public:
  AesIcmKeyDerivation();
  AesIcmKeyDerivation(bool a);
  AesIcmKeyDerivation(u_int16_t key_length);
  AesIcmKeyDerivation(bool a, u_int16_t key_length);
  ~AesIcmKeyDerivation();

  static const u_int16_t DEFAULT_KEY_LENGTH = 128;
  static const u_int16_t CTR_LENGTH = 16;
  static const u_int16_t SALT_LENGTH = 14;
   
  void init(Buffer key, Buffer salt, std::string passphrase = "");
  bool generate(kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, Buffer& key);

  std::string printType();

private:
  void updateMasterKey();

  bool calcCtr(kd_dir_t dir, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr);

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
    ar & boost::serialization::base_object<KeyDerivation>(*this);
	}

#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_[2];
#else
  AES_KEY aes_key_[2];
  u_int8_t ecount_buf_[2][AES_BLOCK_SIZE];
#endif

  key_store_t key_store_[2][KD_LABEL_COUNT];

#ifdef _MSC_VER
  #pragma pack(push, 1)
#endif  
  union ATTR_PACKED key_derivation_aesctr_ctr_union {
    u_int8_t buf_[CTR_LENGTH];
	struct ATTR_PACKED {
      u_int8_t buf_[SALT_LENGTH];
      u_int16_t zero_;
    } salt_;
	struct ATTR_PACKED {
      u_int8_t fill_[SALT_LENGTH - sizeof(u_int8_t) - sizeof(seq_nr_t)];
      u_int8_t label_;
      seq_nr_t r_;
      u_int16_t zero_;
    } params_;
    struct ATTR_PACKED {
      u_int8_t fill_[SALT_LENGTH - sizeof(u_int8_t) - 2 - sizeof(seq_nr_t)];
      u_int8_t label_;
      u_int8_t r_fill_[2];
      seq_nr_t r_;
      u_int16_t zero_;
    } params_compat_;
  } ctr_[2];
#ifdef _MSC_VER  
  #pragma pack(pop)
#endif
};

#endif

#endif

