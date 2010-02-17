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

#ifndef ANYTUN_anytunError_h_INCLUDED
#define ANYTUN_anytunError_h_INCLUDED

#include <sstream>
#include <boost/system/system_error.hpp>
#include "datatypes.h"

#define STERROR_TEXT_MAX 200

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>

class AnytunGpgError
{
public:
  AnytunGpgError(gcry_error_t e) : err_(e) {};
  gcry_error_t err_;
};
std::ostream& operator<<(std::ostream& stream, AnytunGpgError const& value);
#endif
#endif

class AnytunErrno
{
public:
  AnytunErrno(system_error_t e) : err_(e) {};
  system_error_t err_;
};
std::ostream& operator<<(std::ostream& stream, AnytunErrno const& value);

class ErrorStringBuilder
{
public:
  ErrorStringBuilder(ErrorStringBuilder const& src) { stream << src.stream.str(); };
  ErrorStringBuilder() {};
  ~ErrorStringBuilder() { throw std::runtime_error(stream.str()); };

  template<class T>
  std::ostream& operator<<(T const& value) { return stream << value; }

private:
  std::stringstream stream;
};

class AnytunError
{
public:
  static ErrorStringBuilder throwErr() { return ErrorStringBuilder(); }
};

#endif
