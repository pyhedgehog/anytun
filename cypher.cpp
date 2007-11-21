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

#include "cypher.h"
#include "keyDerivation.h"


extern "C" {
#include <gcrypt.h>
}

void Cypher::cypher(Buffer& buf, seq_nr_t seq_nr, sender_id_t sender_id)
{
  Buffer stream = getBitStream(buf.getLength(), seq_nr, sender_id);
  exor(buf, stream);
}

void Cypher::exor(Buffer& buf, const Buffer& bit_stream)
{
  try
  {
    for(u_int32_t i; i<buf.getLength(); ++i)
      buf[i] ^= bit_stream[i];
  }
  catch(std::out_of_range& o) {}
}

Buffer NullCypher::getBitStream(u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id)
{
  Buffer buf(length);
  for(u_int32_t i; i<length; ++i)
    buf[i] = 0;
  return buf;
}


const char* AesIcmCypher::MIN_GCRYPT_VERSION = "1.2.3";
bool AesIcmCypher::gcrypt_initialized_ = false;


AesIcmCypher::AesIcmCypher() : salt_(Buffer(14))
{
  gcry_error_t err;

  // No other library has already initialized libgcrypt.
  if( !gcry_control(GCRYCTL_ANY_INITIALIZATION_P) )
  {
    if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
      std::cerr << "Invalid Version of libgcrypt, should be >= ";
      std::cerr << MIN_GCRYPT_VERSION << std::endl;
      return;
    }

    /* Allocate a pool of secure memory.  This also drops priviliges
       on some systems. */
    err = gcry_control(GCRYCTL_INIT_SECMEM, GCRYPT_SEC_MEM, 0);
    if( err ) {
      std::cerr << "Failed to allocate " << GCRYPT_SEC_MEM << "bytes of secure memory: ";
      std::cerr << gpg_strerror( err ) << std::endl;
      return;
    }

    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    if( err ) {
      std::cerr << "Failed to finish the initialization of libgcrypt";
      std::cerr << gpg_strerror( err ) << std::endl;
      return;
    } else {
      std::cout << "AesIcmCypher::AesIcmCypher: libgcrypt init finished" << std::endl;
    }
  }

  gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );

  std::cout << "Keysize: " << gcry_cipher_get_algo_keylen( GCRY_CIPHER_AES128 ) << std::endl;
}


AesIcmCypher::~AesIcmCypher()
{
  gcry_cipher_close( cipher_ );
}


void AesIcmCypher::setKey(Buffer key)
{
  gcry_error_t err;
  err = gcry_cipher_setkey( cipher_, key.getBuf(), 16 );
  if( err )
    std::cerr << "Failed to set cipher key: " << gpg_strerror( err ) << std::endl;
}

void AesIcmCypher::setSalt(Buffer salt)
{
  salt_ = salt;
}

Buffer AesIcmCypher::getBitStream(u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id)
{
  gcry_error_t err;

  Buffer buf(length);

//  // set IV
//  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
//  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
//  //
//  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
//  // sizeof(k_s) = 112 bit, random

  Buffer iv(16), seq, sid;

  sid = sender_id;
  seq = seq_nr;

  iv = (salt_.leftByteShift(2) ^ sid.leftByteShift(8)) ^ sid.leftByteShift(2);

  err = gcry_cipher_setiv( cipher_, iv.getBuf(), 0 );
  if( err )
  {
    std::cerr << "Failed to set cipher IV: " << gpg_strerror( err ) << std::endl;
    return Buffer(0);
  }

  err = gcry_cipher_reset( cipher_ );
  if( err )
  {
    std::cerr << "Failed to reset cipher: " << gpg_strerror( err ) << std::endl;
    return Buffer(0);
  }

  err = gcry_cipher_encrypt( cipher_, buf, buf.getLength(), 0, 0 );
  if( err )
  {
    std::cerr << "Failed to generate cipher bitstream: " << gpg_strerror( err ) << std::endl;
    return Buffer(0);
  }

  return buf;
}

