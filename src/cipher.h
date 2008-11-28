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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"
#include "plainPacket.h"

#ifndef NOCRYPT
#include <gcrypt.h>
#endif

class Cipher
{
public:
  virtual ~Cipher() {};

      // TODO: in should be const but does not work with getBuf() :(
	void encrypt(PlainPacket & in, EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
	void decrypt(EncryptedPacket & in, PlainPacket & out);
  
  virtual void setKey(Buffer& key) = 0;
  virtual void setSalt(Buffer& salt) = 0;

protected:
  virtual u_int32_t cipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0;
  virtual u_int32_t decipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux) = 0; 
};

//****** NullCipher ******

class NullCipher : public Cipher
{
public:
  void setKey(Buffer& key) {};
  void setSalt(Buffer& salt) {};

protected:
  u_int32_t cipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  u_int32_t decipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
};

#ifndef NOCRYPT
//****** AesIcmCipher ******

class AesIcmCipher : public Cipher
{
public:
  AesIcmCipher();
  ~AesIcmCipher();
  void setKey(Buffer& key);
  void setSalt(Buffer& salt);

protected:
  u_int32_t cipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
  u_int32_t decipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

private:
  void calc(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

  gcry_cipher_hd_t cipher_;
  Buffer salt_;
};
#endif

#endif
