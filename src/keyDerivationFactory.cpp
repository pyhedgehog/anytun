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
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl,
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
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string>
#include <stdexcept>

#include "keyDerivationFactory.h"
#include "keyDerivation.h"


KeyDerivation* KeyDerivationFactory::create(std::string const& type)
{
  if(type == "null") {
    return new NullKeyDerivation();
  }
#ifndef NO_CRYPT
  else if(type == "aes-ctr") {
    return new AesIcmKeyDerivation();
  } else if(type == "aes-ctr-128") {
    return new AesIcmKeyDerivation(128);
  } else if(type == "aes-ctr-192") {
    return new AesIcmKeyDerivation(192);
  } else if(type == "aes-ctr-256") {
    return new AesIcmKeyDerivation(256);
  }
#endif
  else {
    throw std::invalid_argument("key derivation prf not available");
  }
}

