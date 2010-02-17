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

#ifndef ANYTUN_cryptinit_hpp_INCLUDED
#define ANYTUN_cryptinit_hpp_INCLUDED

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>

// boost thread callbacks for libgcrypt
static int boost_mutex_init(void** priv)
{
  boost::mutex* lock = new boost::mutex();
  if(!lock) {
    return ENOMEM;
  }
  *priv = lock;
  return 0;
}

static int boost_mutex_destroy(void** lock)
{
  delete reinterpret_cast<boost::mutex*>(*lock);
  return 0;
}

static int boost_mutex_lock(void** lock)
{
  reinterpret_cast<boost::mutex*>(*lock)->lock();
  return 0;
}

static int boost_mutex_unlock(void** lock)
{
  reinterpret_cast<boost::mutex*>(*lock)->unlock();
  return 0;
}

static struct gcry_thread_cbs gcry_threads_boost = {
  GCRY_THREAD_OPTION_USER, NULL,
  boost_mutex_init, boost_mutex_destroy,
  boost_mutex_lock, boost_mutex_unlock
};

#define MIN_GCRYPT_VERSION "1.2.0"

bool initLibGCrypt()
{
  // make libgcrypt thread safe
  // this must be called before any other libgcrypt call
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_boost);

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
#ifndef USE_SSL_CRYPTO
  return initLibGCrypt();
#else
  return true;
#endif
#else
  return true;
#endif
}

#endif
