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

#ifndef _AUTHALGO_H_
#define _AUTHALGO_H_

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"

#include <gcrypt.h>

class AuthAlgo
{
public:
  AuthAlgo() {};
  virtual ~AuthAlgo() {};

  /**
   * set the key for the auth algo
   * @param key key for hmac calculation
   */
  virtual void setKey(Buffer& key) = 0;

  /**
   * generate the mac
   * @param packet the packet to be authenticated
   */
  virtual void generate(EncryptedPacket& packet) = 0;

  /**
   * check the mac
   * @param packet the packet to be authenticated
   */
  virtual bool checkTag(EncryptedPacket& packet) = 0;

  /**
   * get the maximum size of the auth algo
   */
  virtual u_int32_t getMaxLength() = 0;
};

//****** NullAuthAlgo ******

class NullAuthAlgo : public AuthAlgo
{
public:
  void setKey(Buffer& key) {};
  void generate(EncryptedPacket& packet);
  bool checkTag(EncryptedPacket& packet);
  u_int32_t getMaxLength();

  static const u_int32_t MAX_LENGTH_ = 0;
};

#ifndef NOCRYPT
//****** Sha1AuthAlgo ******
//* HMAC SHA1 Auth Tag Generator Class

class Sha1AuthAlgo : public AuthAlgo
{
public:
  Sha1AuthAlgo();
  ~Sha1AuthAlgo();

  void setKey(Buffer& key);
  void generate(EncryptedPacket& packet);
  bool checkTag(EncryptedPacket& packet);
  u_int32_t getMaxLength();

  static const u_int32_t MAX_LENGTH_ = 20;

private:
  gcry_md_hd_t ctx_;
};
#endif

#endif
