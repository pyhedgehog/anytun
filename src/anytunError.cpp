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

#include "anytunError.h"

#include <sstream>
#include <boost/system/system_error.hpp>

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
std::ostream& operator<<(std::ostream& stream, AnytunGpgError const& value)
{
  char buf[STERROR_TEXT_MAX];
  buf[0] = 0;
  gpg_strerror_r(value.err_, buf, STERROR_TEXT_MAX);
  return stream << buf;
}
#endif
#endif

std::ostream& operator<<(std::ostream& stream, AnytunErrno const& value)
{
  boost::system::system_error err(boost::system::error_code(value.err_, boost::system::get_system_category()));
  return stream << err.what();
}
