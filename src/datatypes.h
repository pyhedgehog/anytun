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

#ifndef ANYTUN_datatypes_h_INCLUDED
#define ANYTUN_datatypes_h_INCLUDED

#include <boost/cstdint.hpp>
#include <boost/integer_traits.hpp>
#include <boost/config.hpp>

#ifndef BOOST_NO_NOEXCEPT
#define NOEXCEPT(x) noexcept(x)
#else
#define NOEXCEPT(x)
#endif

// should not be necessary on GCC, #ifdef + #include <stdint.h> should do the job; still required on MS VC++9, though.
using boost::int8_t;
using boost::uint8_t;
using boost::int16_t;
using boost::uint16_t;
using boost::int32_t;
using boost::uint32_t;
using boost::int64_t;
using boost::uint64_t;

typedef uint32_t window_size_t;

typedef uint32_t seq_nr_t;
#define SEQ_NR_MAX 0xFFFFFFFF
typedef uint16_t sender_id_t;
typedef uint16_t payload_type_t;
typedef uint16_t mux_t;
typedef uint32_t satp_prf_label_t;

typedef enum { ANY, IPV4_ONLY, IPV6_ONLY } ResolvAddrType;

#ifndef _MSC_VER
#define ATTR_PACKED __attribute__((__packed__))
#else
#define ATTR_PACKED
#endif

#if !defined(_MSC_VER) && !defined(MINGW)
typedef int system_error_t;
#else
#include <windows.h>
typedef DWORD system_error_t;
#endif

#define MAX_PACKET_LENGTH 1600

#endif
