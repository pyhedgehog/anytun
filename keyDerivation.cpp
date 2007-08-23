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

extern "C" {
#include <srtp/crypto_kernel.h>
}

err_status_t KeyDerivation::init(Buffer key, Buffer salt)
{
  extern cipher_type_t aes_icm;
  err_status_t status = err_status_ok;

  salt_ = salt;

  // allocate cipher
  // FIXXME: why we do not can do this??
//  status = cipher_type_alloc(&aes_icm, &cipher_, key.getLength());
  status = cipher_type_alloc(&aes_icm, &cipher_, 30);
  if( status )
    return status;

  // init cipher
  status = cipher_init(cipher_, key.getBuf(), direction_any);
  if( status )
    cipher_dealloc(cipher_);

  return status;
}

err_status_t KeyDerivation::setLogKDRate(const uint8_t log_rate)
{
  if( log_rate < 49 )
  {
    ld_kdr_ = log_rate;
    return err_status_ok;
  }
  return err_status_bad_param;
}


err_status_t KeyDerivation::generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key, uint32_t length)
{
  err_status_t status = err_status_ok;
  v128_t iv, salt, key_id;
  uint8_t r = 0;

  v128_set_to_zero(&iv);
  v128_set_to_zero(&salt);
  v128_set_to_zero(&key_id);

  // look at: http://tools.ietf.org/html/rfc3711#section-4.3
  if( ld_kdr_ == -1 )    // means key_derivation_rate = 0
    r = 0;
  else
    // FIXXME: kdr can be greater than 2^32 (= 2^48)
    r = seq_nr / ( 0x01 << ld_kdr_ );

  key_id.v32[0] = (label << 8);
  key_id.v32[0] += r;

  v128_copy_octet_string(&salt, salt_.getBuf());
  v128_xor(&iv, &salt, &key_id);

  status = cipher_set_iv(cipher_, &iv);
  if( status )
  {
    KeyDerivation::clear();
    return status;
  }

  /* generate keystream output */
  status = cipher_output(cipher_, key, length);

  return status;
}


err_status_t KeyDerivation::clear() 
{
  return cipher_dealloc(cipher_);
}

