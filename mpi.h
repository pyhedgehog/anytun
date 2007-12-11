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

#ifndef _MPI_H_
#define _MPI_H_

#include "datatypes.h"
#include "buffer.h"

#include <gcrypt.h>


class Mpi
{
public:
  Mpi();
  virtual ~Mpi();
  Mpi(u_int8_t length);
  Mpi(const Mpi &src);
  Mpi(const u_int8_t * src, u_int32_t len);
  void operator=(const Mpi &src);
  void operator=(long unsigned int);
  Mpi operator+(const Mpi &b) const;
  Mpi operator+(const long unsigned int &b) const;
  Mpi operator^(const Mpi &b) const;
  Mpi operator*(const unsigned long int n) const;

  void rShift(u_int8_t n);            // LSB on the right side!
  Mpi mul2exp(u_int32_t e) const;     // value * 2^e
  void clearHighBit(u_int32_t n);
  Buffer getBuf(u_int32_t min_len=0) const;
  u_int32_t getLen() const;
 
protected:
  gcry_mpi_t val_;
};



#endif
