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


#include "log.h"
#include "keyDerivation.h"
#include "mpi.h"
#include "threadUtils.hpp"

#include <stdexcept>
#include <iostream>
#include <string>

#include <gcrypt.h>


const char* KeyDerivation::MIN_GCRYPT_VERSION = "1.2.3";

void KeyDerivation::init(Buffer key, Buffer salt)
{
  Lock lock(mutex_);
  gcry_error_t err;

  // No other library has already initialized libgcrypt.
  if( !gcry_control(GCRYCTL_ANY_INITIALIZATION_P) )
  {
    if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
      cLog.msg(Log::PRIO_ERR) << "KeyDerivation::init: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION;
      return;
    }

    // do NOT allocate a pool of secure memory!
    // this is NOT thread safe!

    //    /* Allocate a pool of 16k secure memory.  This also drops priviliges
    //     *      on some systems. */
    //    err = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    //    if( err )
    //    {
    //      std::cerr << "Failed to allocate 16k secure memory: " << gpg_strerror( err ) << std::endl;
    //      return;
    //    }

    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    if( err ) {
      cLog.msg(Log::PRIO_ERR) << "KeyDerivation::init: Failed to finish the initialization of libgcrypt: " << gpg_strerror( err );
      return;
    } else {
      cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation::init: libgcrypt init finished";
    }
  }

  err = gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::init: Failed to open cipher: " << gpg_strerror( err );
    return;
  }

  // FIXXME: hardcoded keysize!
  err = gcry_cipher_setkey( cipher_, key.getBuf(), 16 );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::init: Failed to set cipher key: " << gpg_strerror( err );

  salt_ = SyncBuffer(salt);
}

void KeyDerivation::setLogKDRate(const uint8_t log_rate)
{
  Lock lock(mutex_);
  if( log_rate < 49 )
    ld_kdr_ = log_rate;
}


void KeyDerivation::generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key, u_int32_t length) 
{
  ////Lock lock(mutex_);
  gcry_error_t err;

  Mpi r;
  Mpi key_id(128);
  Mpi iv(128);

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
    r = static_cast<long unsigned int>(seq_nr / ( 0x01 << ld_kdr_ ));

  r = r.mul2exp(8);
  key_id = r + static_cast<long unsigned int>(label);

  Mpi salt = Mpi(salt_.getBuf(), salt_.getLength());
  iv = key_id ^ salt;

  err = gcry_cipher_reset( cipher_ );
  if( err ) 
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to reset cipher: " << gpg_strerror( err );

  iv.clearHighBit(129);  
  
  err = gcry_cipher_setiv( cipher_ , iv.getBuf().getBuf(), iv.getBuf().getLength());
  if( err )
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to set IV: " << gpg_strerror( err );

  err = gcry_cipher_encrypt( cipher_, key, length, 0, 0 );
 
  if( err ) 
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to generate cipher bitstream: " << gpg_strerror( err );
}


void KeyDerivation::clear() 
{
  Lock lock(mutex_);
  gcry_cipher_close( cipher_ );
}

u_int32_t KeyDerivation::bufferGetLength() const
{
	return salt_.getLength();
}
