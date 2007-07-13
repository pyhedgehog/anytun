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

#include "datatypes.h"

#include "cypher.h"

extern "C" {
#include <srtp/crypto_kernel.h>
}

void Cypher::cypher(Buffer& buf)
{
  Buffer stream = getBitStream(buf.getLength());
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

Buffer NullCypher::getBitStream(u_int32_t length)
{
  Buffer buf(length);
  for(u_int32_t i; i<length; ++i)
    buf[i] = 0;
  return buf;
}

void AesIcmCypher::cypher(Buffer& buf)
{
}

Buffer AesIcmCypher::getBitStream(u_int32_t length)
{
  Buffer buf(length);
  extern cipher_type_t aes_icm;
  err_status_t status;
  cipher_t* cipher = NULL;
  const uint8_t key = 0x42;
  uint8_t idx[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34
  };


  status = cipher_type_alloc(&aes_icm, &cipher, sizeof(key));
  status = cipher_init(cipher, &key, direction_encrypt);

  status = cipher_set_iv(cipher, idx);
  
  status = cipher_output(cipher, buf, length);
  status = cipher_dealloc(cipher);
  return buf;
}


