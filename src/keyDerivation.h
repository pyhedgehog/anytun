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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KEYDERIVATION_H_
#define _KEYDERIVATION_H_

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include "syncBuffer.h"

#include <gcrypt.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


typedef enum {
  LABEL_SATP_ENCRYPTION  = 0x00,
  LABEL_SATP_MSG_AUTH    = 0x01,
  LABEL_SATP_SALT        = 0x02,
} satp_prf_label;


class KeyDerivation
{
public:
  KeyDerivation() : ld_kdr_(0), master_salt_(0), master_key_(0) {};
  virtual ~KeyDerivation() {};

  void setLogKDRate(const u_int8_t ld_rate);

  virtual void init(Buffer key, Buffer salt) = 0;
  virtual void generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key) = 0;

  virtual std::string printType() { return "KeyDerivation"; };

protected:
  virtual void updateMasterKey() = 0;
  
	KeyDerivation(const KeyDerivation & src);
	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
 		Lock lock(mutex_);
    ar & ld_kdr_;
    ar & master_salt_;
    ar & master_key_;
    updateMasterKey();
	}

  int8_t ld_kdr_;             // ld(key_derivation_rate)
  SyncBuffer master_salt_;
  SyncBuffer master_key_;

  Mutex mutex_;
};

BOOST_IS_ABSTRACT(KeyDerivation)

//****** NullKeyDerivation ******

class NullKeyDerivation : public KeyDerivation
{
public:
  NullKeyDerivation() {};
  ~NullKeyDerivation() {};

  void init(Buffer key, Buffer salt) {};
  void generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key);

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

//****** AesIcmKeyDerivation ******

class AesIcmKeyDerivation : public KeyDerivation
{
public:
  AesIcmKeyDerivation() : cipher_(NULL) {};
  ~AesIcmKeyDerivation();
  
  void init(Buffer key, Buffer salt);
  void generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key);

  std::string printType() { return "AesIcmKeyDerivation"; };

private:
  void updateMasterKey();

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
    ar & boost::serialization::base_object<KeyDerivation>(*this);
	}

  gcry_cipher_hd_t cipher_;
};

#endif

