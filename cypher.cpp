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

#include <stdexcept>
#include <iostream>
#include <string>
#include <cstdio>
#include <gcrypt.h>

#include "cypher.h"
#include "mpi.h"
#include "log.h"

void Cypher::encrypt(const PlainPacket & in,EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id)
{
	cypher(out.payload_, in.complete_payload_ , in.complete_payload_length_, seq_nr, sender_id);
	out.setSenderId(sender_id);
	out.setSeqNr(seq_nr);
	out.setPayloadLength(in.complete_payload_length_);
}

void Cypher::decrypt(const EncryptedPacket & in,PlainPacket & out)
{
	cypher(out.complete_payload_, in.payload_ , in.payload_length_, in.getSeqNr(), in.getSenderId());
	out.setCompletePayloadLength(in.payload_length_);
}

void NullCypher::cypher(u_int8_t * out, u_int8_t * in, u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id)
{
	std::memcpy(out, in, length );
}

const char* AesIcmCypher::MIN_GCRYPT_VERSION = "1.2.3";

AesIcmCypher::AesIcmCypher() : salt_(Buffer(14))
{
  gcry_error_t err;

  // No other library has already initialized libgcrypt.
  if( !gcry_control(GCRYCTL_ANY_INITIALIZATION_P) )
  {
    if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
      cLog.msg(Log::PRIO_ERR) << "AesIcmCypher::AesIcmCypher: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION;
      return;
    }

    /* Allocate a pool of secure memory.  This also drops priviliges
       on some systems. */
    err = gcry_control(GCRYCTL_INIT_SECMEM, GCRYPT_SEC_MEM, 0);
    if( err ) {
      cLog.msg(Log::PRIO_ERR) << "Failed to allocate " << GCRYPT_SEC_MEM << "bytes of secure memory: " << gpg_strerror( err );
      return;
    }

    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    if( err ) {
      cLog.msg(Log::PRIO_CRIT) << "AesIcmCypher::AesIcmCypher: Failed to finish the initialization of libgcrypt: " << gpg_strerror( err );
      return;
    } else {
      cLog.msg(Log::PRIO_DEBUG) << "AesIcmCypher::AesIcmCypher: libgcrypt init finished";
    }
  }

  err = gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );
  if( err )
    cLog.msg(Log::PRIO_CRIT) << "AesIcmCypher::AesIcmCypher: Failed to open cypher";
}


AesIcmCypher::~AesIcmCypher()
{
  gcry_cipher_close( cipher_ );
  cLog.msg(Log::PRIO_DEBUG) << "AesIcmCypher::~AesIcmCypher: closed cipher";
}


void AesIcmCypher::setKey(Buffer key)
{
  gcry_error_t err;
  // FIXXME: hardcoded keysize
  err = gcry_cipher_setkey( cipher_, key.getBuf(), 16 );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "AesIcmCypher::setKey: Failed to set cipher key: " << gpg_strerror( err );
}

void AesIcmCypher::setSalt(Buffer salt)
{
  salt_ = salt;
}

void AesIcmCypher::cypher(u_int8_t *  out, u_int8_t * in, u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id)
{
  gcry_error_t err;

  // set the IV
  //==========================================================================
  //  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
  //  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
  //  //
  //  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  //  //  sizeof(k_s) = 112 bit, random

  Mpi iv(128);
  Mpi salt = Mpi(salt_.getBuf(), salt_.getLength());
  Mpi sid = sender_id;
  Mpi seq = seq_nr;

  iv = salt.mul2exp(16) ^ sid.mul2exp(64) ^ seq.mul2exp(16);

  u_int8_t *iv_buf = iv.getNewBuf(16);
  err = gcry_cipher_setiv( cipher_, iv_buf, 16 );
  delete[] iv_buf;
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCypher: Failed to set cipher IV: " << gpg_strerror( err );
    return;
  }

  err = gcry_cipher_reset( cipher_ );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCypher: Failed to reset cipher: " << gpg_strerror( err );
    return;
  }

  err = gcry_cipher_encrypt( cipher_, out, length, in, length );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCypher: Failed to generate cipher bitstream: " << gpg_strerror( err );
    return;
  }
}

