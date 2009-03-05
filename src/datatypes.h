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

#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#include <boost/cstdint.hpp>
#include <boost/integer_traits.hpp>

typedef boost::uint8_t u_int8_t;
typedef boost::uint16_t u_int16_t;
typedef boost::uint32_t u_int32_t;
typedef boost::uint64_t u_int64_t;
typedef boost::int8_t int8_t;
typedef boost::int16_t int16_t;
typedef boost::int32_t int32_t;
typedef boost::int64_t int64_t;

typedef u_int32_t window_size_t;

typedef u_int32_t seq_nr_t;
#define SEQ_NR_MAX 0xFFFFFFFF
typedef u_int16_t sender_id_t;
typedef u_int16_t payload_type_t;
typedef u_int16_t mux_t;

typedef enum { ANY, IPV4_ONLY, IPV6_ONLY } ResolvAddrType;

#ifndef _MSC_VER
#define ATTR_PACKED __attribute__((__packed__))
typedef int system_error_t;
#else
#include <windows.h>
#define ATTR_PACKED
typedef DWORD system_error_t;
#endif	  

#endif
