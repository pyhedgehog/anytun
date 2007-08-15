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

#include "cypher.h"

extern "C" {
#include <srtp/crypto_kernel.h>
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


void AesIcmCypher::cypher(Buffer& buf, seq_nr_t seq_nr, sender_id_t sender_id)
{
  extern cipher_type_t aes_icm;
  err_status_t status = err_status_ok;
  cipher_t* cipher = NULL;
  uint32_t length = 0;

  uint8_t key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
  };

  v128_t iv;
  v128_set_to_zero(&iv);

  // allocate cipher
  status = cipher_type_alloc(&aes_icm, &cipher, 30);

  // init cipher
  status = cipher_init(cipher, key, direction_any);

  //set iv
  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
  //
  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)

  // sizeof(k_s) = 112, random

  iv.v32[0] ^= 0;
  iv.v32[1] ^= sender_id; 
  iv.v32[2] ^= (seq_nr >> 16);
  iv.v32[3] ^= (seq_nr << 16);


  status = cipher_set_iv(cipher, &iv);

  length = buf.getLength();
  
  status = cipher_encrypt(cipher, buf, &length);
  status = cipher_dealloc(cipher);
}

