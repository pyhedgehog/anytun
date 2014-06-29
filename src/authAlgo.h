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

#ifndef ANYTUN_authAlgo_h_INCLUDED
#define ANYTUN_authAlgo_h_INCLUDED

#include "datatypes.h"
#include "buffer.h"
#include "encryptedPacket.h"

#ifndef NO_CRYPT

#if defined(USE_SSL_CRYPTO)
#include <openssl/hmac.h>
#elif defined(USE_NETTLE)
#include <nettle/hmac.h>
#else  // USE_GCRYPT is the default
#include <gcrypt.h>
#endif

#endif
#include "keyDerivation.h"

class AuthAlgo
{
public:
  AuthAlgo() : dir_(KD_INBOUND) {};
  AuthAlgo(kd_dir_t d) : dir_(d) {};
  virtual ~AuthAlgo() {};

  /**
   * generate the mac
   * @param packet the packet to be authenticated
   */
  virtual void generate(KeyDerivation& kd, EncryptedPacket& packet) = 0;

  /**
   * check the mac
   * @param packet the packet to be authenticated
   */
  virtual bool checkTag(KeyDerivation& kd, EncryptedPacket& packet) = 0;

protected:
  kd_dir_t dir_;
};

//****** NullAuthAlgo ******

class NullAuthAlgo : public AuthAlgo
{
public:
  void generate(KeyDerivation& kd, EncryptedPacket& packet);
  bool checkTag(KeyDerivation& kd, EncryptedPacket& packet);

  static const uint32_t DIGEST_LENGTH = 0;
};

#ifndef NO_CRYPT
//****** Sha1AuthAlgo ******
//* HMAC SHA1 Auth Tag Generator Class

class Sha1AuthAlgo : public AuthAlgo
{
public:
  Sha1AuthAlgo(kd_dir_t d);
  ~Sha1AuthAlgo();

  void generate(KeyDerivation& kd, EncryptedPacket& packet);
  bool checkTag(KeyDerivation& kd, EncryptedPacket& packet);

  static const uint32_t DIGEST_LENGTH = 20;

private:
#if defined(USE_SSL_CRYPTO)
  HMAC_CTX ctx_;
#elif defined(USE_NETTLE)
  struct hmac_sha1_ctx ctx_;
#else  // USE_GCRYPT is the default
  gcry_md_hd_t handle_;
#endif

  Buffer key_;
};
#endif

#endif
