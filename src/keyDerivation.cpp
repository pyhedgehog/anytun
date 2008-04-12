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


void KeyDerivation::setLogKDRate(const uint8_t log_rate)
{
  Lock lock(mutex_);
  if( log_rate < 49 )
    ld_kdr_ = log_rate;
}

//****** NullKeyDerivation ******

void NullKeyDerivation::generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key)
{
  for(u_int32_t i=0; i < key.getLength(); ++i) key[i] = 0;
}

//****** AesIcmKeyDerivation ******

AesIcmKeyDerivation::~AesIcmKeyDerivation()
{
  Lock lock(mutex_);
  if(cipher_)
    gcry_cipher_close( cipher_ );
}

void AesIcmKeyDerivation::updateMasterKey()
{
  if(!cipher_)
    return;

  gcry_error_t err = gcry_cipher_setkey( cipher_, master_key_.getBuf(), master_key_.getLength() );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::updateMasterKey: Failed to set cipher key: " << gpg_strerror( err );
}

void AesIcmKeyDerivation::init(Buffer key, Buffer salt)
{
  Lock lock(mutex_);
  if(cipher_)
    gcry_cipher_close( cipher_ );

  // TODO: hardcoded size
  gcry_error_t err = gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::init: Failed to open cipher: " << gpg_strerror( err );
    return;
  }
  
  master_salt_ = SyncBuffer(salt);
  master_key_ = SyncBuffer(key);

  updateMasterKey();
}

void AesIcmKeyDerivation::generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key) 
{
  Lock lock(mutex_);
  if(!cipher_)
  {
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: cipher not opened";
    return;
  }

  gcry_error_t err = gcry_cipher_reset( cipher_ );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to reset cipher: " << gpg_strerror( err );

  // see at: http://tools.ietf.org/html/rfc3711#section-4.3
  // *  Let r = index DIV key_derivation_rate (with DIV as defined above).
  // *  Let key_id = <label> || r.
  // *  Let x = key_id XOR master_salt, where key_id and master_salt are
  //    aligned so that their least significant bits agree (right-
  //    alignment).
  //

  Mpi r(48); // ld(kdr) <= 48
  if( ld_kdr_ == -1 )    // means key_derivation_rate = 0
    r = 0;  // TODO: no new key should be generated if r == 0, except it is the first time
  else
  {
    Mpi seq(32);
    seq = seq_nr;
    Mpi rate(48);
    rate = 1;
    rate = rate.mul2exp(ld_kdr_);
    r = seq / rate;
  }
      // TODO: generate key only if index % r == 0, except it is the first time

  Mpi key_id(128);                                                   // TODO: hardcoded size
  Mpi l(128);                                                 // TODO: hardcoded size
  l = label;
  key_id = l.mul2exp(48) + r;

  Mpi salt(master_salt_.getBuf(), master_salt_.getLength());
  Mpi x(128);                                                        // TODO: hardcoded size
  x = key_id ^ salt;

  size_t written;
  u_int8_t *ctr_buf = x.mul2exp(16).getNewBuf(&written);         // TODO: hardcoded size
  err = gcry_cipher_setctr( cipher_ , ctr_buf, written );
  delete[] ctr_buf;

  if( err )
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to set CTR: " << gpg_strerror( err );

  for(u_int32_t i=0; i < key.getLength(); ++i) key[i] = 0;
  err = gcry_cipher_encrypt( cipher_, key, key.getLength(), NULL, 0);
  if( err ) 
    cLog.msg(Log::PRIO_ERR) << "KeyDerivation::generate: Failed to generate cipher bitstream: " << gpg_strerror( err );
}

