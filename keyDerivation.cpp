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
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "keyDerivation.h"

#include <stdexcept>
#include <iostream>
#include <string>

extern "C" {
#include <gcrypt.h>
}

const char* KeyDerivation::MIN_GCRYPT_VERSION = "1.2.3";

void KeyDerivation::init(Buffer key, Buffer salt)
{
  gcry_error_t err;

  // No other library has already initialized libgcrypt.
  if( !gcry_control(GCRYCTL_ANY_INITIALIZATION_P) )
  {
    if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
      std::cerr << "Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION << std::endl;
      return;
    }

    /* Allocate a pool of 16k secure memory.  This also drops priviliges
     *      on some systems. */
    err = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    if( err )
    {
      std::cerr << "Failed to allocate 16k secure memory: " << gpg_strerror( err ) << std::endl;
      return;
    }

    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    if( err ) {
      std::cerr << "Failed to finish the initialization of libgcrypt" << gpg_strerror( err ) << std::endl;
      return;
    } else {
      std::cout << "KeyDerivation::init: libgcrypt init finished" << std::endl;
    }
  }

  err = gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );
  if( err )
  {
    std::cerr << "Failed to open cipher: " << gpg_strerror( err ) << std::endl;
    return;
  }

}

void KeyDerivation::setLogKDRate(const uint8_t log_rate)
{
  if( log_rate < 49 )
    ld_kdr_ = log_rate;
}


void KeyDerivation::generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key, u_int32_t length)
{
  gcry_error_t err;
  u_int8_t r = 0;
  Buffer iv(16);

  u_int8_t tmp_key_id[16];

  // see at: http://tools.ietf.org/html/rfc3711#section-4.3
  // *  Let r = index DIV key_derivation_rate (with DIV as defined above).
  // *  Let key_id = <label> || r.
  // *  Let x = key_id XOR master_salt, where key_id and master_salt are
  //    aligned so that their least significant bits agree (right-
  //    alignment).
  //

  if( ld_kdr_ == -1 )    // means key_derivation_rate = 0
    r = 0;
  else
    // FIXXME: kdr can be greater than 2^32 (= 2^48)
    r = seq_nr / ( 0x01 << ld_kdr_ );



  // FIXXME: why i cant access key_id via operator []? 
  for(u_int8_t i=0; i<sizeof(tmp_key_id); i++)
    tmp_key_id[i] = 0x00;

  tmp_key_id[0] = r; 
  tmp_key_id[1] = label;

  Buffer key_id(tmp_key_id, 16);

  iv = key_id ^ salt_;

  err = gcry_cipher_reset( cipher_ );
  if( err )
  {
    std::cerr << "Failed to reset cipher: " << gpg_strerror( err ) << std::endl;
  }

  err = gcry_cipher_encrypt( cipher_, key, key.getLength(), 0, 0 );
  if( err )
  {
    std::cerr << "Failed to generate cipher bitstream: " << gpg_strerror( err ) << std::endl;
  }
}


void KeyDerivation::clear() 
{
  gcry_cipher_close( cipher_ );
}

template<class Archive>
void KeyDerivation::serialize(Archive & ar, const unsigned int version)
{
	ar & ld_kdr_;
	ar & salt_;
}
