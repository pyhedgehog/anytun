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

#ifndef _CYPHER_H_
#define _CYPHER_H_

#include "buffer.h"


class Cypher
{
public:
  Cypher() {};
  virtual ~Cypher() {};
  
  void cypher(Buffer& buf);
  
protected:
  void exor(Buffer& buf, const Buffer& bit_stream);
  virtual Buffer getBitStream(u_int32_t length) = 0;
};

class NullCypher : public Cypher
{
protected:
  Buffer getBitStream(u_int32_t length);
};

class AesIcmCypher : public Cypher
{
public:
  void cypher(Buffer& buf);

protected:
  Buffer getBitStream(u_int32_t length);
};

#endif
