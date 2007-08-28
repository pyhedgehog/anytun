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
#include <vector>
#include <iostream>

#include "cypher.h"
#include "keyDerivation.h"


extern "C" {
#include <srtp/crypto_kernel.h>
}

void Cypher::cypher(Buffer& buf, seq_nr_t seq_nr, sender_id_t sender_id)
{
  std::cout << "Cypher::cypher called" << std::endl;
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


void AesIcmCypher::setKey(Buffer key)
{
  key_ = key;
}

void AesIcmCypher::setSalt(Buffer salt)
{
  salt = salt;
}

Buffer AesIcmCypher::getBitStream(u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id)
{
  Buffer buf(length);
  extern cipher_type_t aes_icm;
  err_status_t status = err_status_ok;
  cipher_t* cipher = NULL;
  v128_t iv, sid, seq, salt;

  v128_set_to_zero(&iv);
  v128_set_to_zero(&sid);
  v128_set_to_zero(&seq);
  v128_set_to_zero(&salt);

  std::cout << "AesIcmCypher::getBitStream called" << std::endl;
  // allocate cipher
  // FIXXME: why we do not can do this???
//  status = cipher_type_alloc(&aes_icm, &cipher, key_.getLength());
  status = cipher_type_alloc(&aes_icm, &cipher, 30);
  if( status ) 
    return Buffer(0);

  // init cipher
  status = cipher_init(cipher, key_.getBuf(), direction_any);
  if( status )
  {
    cipher_dealloc(cipher);
    return Buffer(0);
  }

  // set IV
  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
  //
  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  // sizeof(k_s) = 112 bit, random

  seq.v64[0] = seq_nr;
  sid.v64[0] = sender_id;
  v128_copy_octet_string(&salt, salt_.getBuf());
  v128_left_shift(&salt, 16);
  v128_left_shift(&sid, 64);
  v128_left_shift(&seq, 16);

  v128_xor(&iv, &salt, &sid);
  v128_xor(&iv, &iv, &seq);

  status = cipher_set_iv(cipher, &iv);
  if( status )
    cipher_dealloc(cipher);

  status = cipher_output(cipher, buf, length);
  status = cipher_dealloc(cipher);
  return buf;
}

//
//void AesIcmCypher::cypher(Buffer& buf, seq_nr_t seq_nr, sender_id_t sender_id)
//{
//  extern cipher_type_t aes_icm;
//  err_status_t status = err_status_ok;
//  cipher_t* cipher = NULL;
//  uint32_t length = 0;
//  v128_t iv, sid, seq, salt;
//
//  v128_set_to_zero(&iv);
//  v128_set_to_zero(&sid);
//  v128_set_to_zero(&seq);
//  v128_set_to_zero(&salt);
//
//  std::cout << "AesIcmCypher::cypher called" << std::endl;
//  // allocate cipher
//  // FIXXME: why we do not can do this???
////  status = cipher_type_alloc(&aes_icm, &cipher, key_.getLength());
//  status = cipher_type_alloc(&aes_icm, &cipher, 30);
//  if( status ) 
//    return;
//
//  // init cipher
//  status = cipher_init(cipher, key_.getBuf(), direction_any);
//  if( status )
//  {
//    cipher_dealloc(cipher);
//    return;
//  }
//
//  // set IV
//  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
//  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
//  //
//  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
//  // sizeof(k_s) = 112 bit, random
//
////  iv.v32[0] ^= 0;
////  iv.v32[1] ^= sender_id; 
////  iv.v32[2] ^= (seq_nr >> 16);
////  iv.v32[3] ^= (seq_nr << 16);
//
//  seq.v64[0] = seq_nr;
//  sid.v64[0] = sender_id;
//  v128_copy_octet_string(&salt, salt_.getBuf());
//  v128_left_shift(&salt, 16);
//  v128_left_shift(&sid, 64);
//  v128_left_shift(&seq, 16);
//
//  v128_xor(&iv, &salt, &sid);
//  v128_xor(&iv, &iv, &seq);
//
//  status = cipher_set_iv(cipher, &iv);
//  if( status )
//    cipher_dealloc(cipher);
//
//  length = buf.getLength();
//  
//  status = cipher_encrypt(cipher, buf, &length);
//  status = cipher_dealloc(cipher);
//}
//
