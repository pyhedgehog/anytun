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

#ifndef ANYTUN_cryptinit_hpp_INCLUDED
#define ANYTUN_cryptinit_hpp_INCLUDED

#ifndef NO_CRYPT

#if defined(USE_GCRYPT)
#include <gcrypt.h>

#if defined(BOOST_HAS_PTHREADS)
// boost thread callbacks for libgcrypt
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#else
#error You can not use gcrypt without pthreads - please configure Boost to use pthreads!
#endif

#define MIN_GCRYPT_VERSION "1.2.0"

bool initLibGCrypt()
{
#if defined(BOOST_HAS_PTHREADS)
  // make libgcrypt thread safe
  // this must be called before any other libgcrypt call
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#else
#error You can not use gcrypt without pthreads - please configure Boost to use pthreads!
#endif

  // this must be called right after the GCRYCTL_SET_THREAD_CBS command
  // no other function must be called till now
  if(!gcry_check_version(MIN_GCRYPT_VERSION)) {
    std::cout << "initLibGCrypt: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION << std::endl;
    return false;
  }

  gcry_error_t err = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  if(err) {
    std::cout << "initLibGCrypt: Failed to disable secure memory: " << AnytunGpgError(err) << std::endl;
    return false;
  }

  // Tell Libgcrypt that initialization has completed.
  err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
  if(err) {
    std::cout << "initLibGCrypt: Failed to finish initialization: " << AnytunGpgError(err) << std::endl;
    return false;
  }

  cLog.msg(Log::PRIO_NOTICE) << "initLibGCrypt: libgcrypt init finished";
  return true;
}
#endif

#endif

bool initCrypto()
{
#ifndef NO_CRYPT

#if defined(USE_SSL_CRYPTO)
  return true;
#elif defined(USE_NETTLE)
  return true;
#else  // USE_GCRYPT is the default
  return initLibGCrypt();
#endif

#else
  return true;
#endif
}

#endif
