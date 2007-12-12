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

#include "authAlgo.h"
#include "log.h"
#include "buffer.h"

#include <gcrypt.h>


AuthTag NullAuthAlgo::calc(const Buffer& buf)
{
  return AuthTag(0);
}

const char* Sha1AuthAlgo::MIN_GCRYPT_VERSION = "1.2.3";

// HMAC_SHA1
Sha1AuthAlgo::Sha1AuthAlgo() : ctx_(NULL)
{
  gcry_error_t err;
  // No other library has already initialized libgcrypt.
  if( !gcry_control(GCRYCTL_ANY_INITIALIZATION_P) )
  {
    if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
      cLog.msg(Log::PRIO_ERR) << "Sha1AuthAlgo::Sha1AuthAlgo: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION;
      return;
    }
    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    if( err ) {
      cLog.msg(Log::PRIO_CRIT) << "Sha1AuthAlgo::Sha1AuthAlgo: Failed to finish the initialization of libgcrypt: " << gpg_strerror( err );
      return;
    } else {
      cLog.msg(Log::PRIO_DEBUG) << "Sha1AuthAlgo::Sha1AuthAlgo: libgcrypt init finished";
    }
  }
  err = gcry_md_open( &ctx_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC );
  if( err )
    cLog.msg(Log::PRIO_CRIT) << "Sha1AuthAlgo::Sha1AuthAlgo: Failed to open message digest algo";
}

Sha1AuthAlgo::~Sha1AuthAlgo()
{
  gcry_md_close( ctx_ );
  cLog.msg(Log::PRIO_DEBUG) << "Sha1AuthAlgo::~Sha1AuthAlgo: closed hmac handler";
}

void Sha1AuthAlgo::setKey(Buffer key)
{
  gcry_error_t err;
  err = gcry_md_setkey( ctx_, key.getBuf(), key.getLength() );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "Sha1AuthAlgo::setKey: Failed to set cipher key: " << gpg_strerror( err );
}


AuthTag Sha1AuthAlgo::calc(const Buffer& buf)
{
  // gcry_error_t err;
  Buffer hmac;  //80bit

  gcry_md_write( ctx_, static_cast<Buffer>(buf).getBuf(), buf.getLength() );
  gcry_md_final( ctx_ );
  hmac = Buffer(gcry_md_read( ctx_, 0 ), 10);
  return hmac;
}


