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

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"
#include "plainPacket.h"

#include <gcrypt.h>


class Cypher
{
public:
  Cypher() {};
  virtual ~Cypher() {};
 
  void setKey(Buffer key) {};
  void setSalt(Buffer salt) {};
	void encrypt(const PlainPacket & in,EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id);
	void decrypt(const EncryptedPacket & in,PlainPacket & out);
private:
  virtual void cypher(u_int8_t * in, u_int8_t * out, u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id) {};
};

//****** NullCypher ******

class NullCypher : public Cypher
{
public:
  NullCypher() {};
  ~NullCypher() {};
protected:
  void cypher(u_int8_t * in, u_int8_t * out, u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id);
};

//****** AesIcmCypher ******

class AesIcmCypher : public Cypher
{
public:
  AesIcmCypher();
  ~AesIcmCypher();
  void setKey(Buffer key);
  void setSalt(Buffer salt);

protected:
  void cypher(u_int8_t * in, u_int8_t * out, u_int32_t length, seq_nr_t seq_nr, sender_id_t sender_id);
  gcry_cipher_hd_t cipher_;
  Buffer salt_;
};


#endif
