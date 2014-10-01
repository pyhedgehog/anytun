/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "openssl.h"
#include <openssl/aes.h>

namespace crypto {

Openssl::~Openssl()
{

}


void Openssl::calcMasterKeySalt(std::string passphrase, uint16_t length, Buffer& masterkey , Buffer& mastersalt)
{

}

uint32_t Openssl::cipher(uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, const Buffer& masterkey, const Buffer& mastersalt, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  return ilen>olen ? ilen : olen;
}

uint32_t Openssl::decipher(uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, const Buffer& masterkey, const Buffer& mastersalt, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  return ilen>olen ? ilen : olen;
}

std::string Openssl::printType()
{
  return "Openssl";
}

//static
bool Openssl::init()
{
  return true;
}

}
