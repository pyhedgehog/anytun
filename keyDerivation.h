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

#ifndef _KEYDERIVATION_H_
#define _KEYDERIVATION_H_

#include "datatypes.h"
#include "buffer.h"


extern "C" {
  #include <srtp/crypto_kernel.h>
}


typedef enum {
  label_satp_encryption  = 0x00,
  label_satp_msg_auth    = 0x01,
  label_satp_salt        = 0x02,
} satp_prf_label;

class KeyDerivation
{
public:
  KeyDerivation() : ld_kdr_(-1), cipher_(NULL) {};
  virtual ~KeyDerivation() {};

  err_status_t init(Buffer key, Buffer salt);
  err_status_t setLogKDRate(const uint8_t ld_rate);
  err_status_t generate(satp_prf_label label, seq_nr_t seq_nr, Buffer& key, uint32_t length);
  err_status_t clear();

protected:
  int8_t ld_kdr_;     // ld(key_derivation_rate)
  Buffer salt_;

  cipher_t* cipher_;
};

#endif
