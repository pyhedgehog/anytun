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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MPI_H_
#define _MPI_H_

#include "datatypes.h"
#include "buffer.h"

#include <gcrypt.h>


/**
 * This class is a wrapper for the libgcrypt multi precision integer library [1]
 * [1] http://www.gnupg.org/documentation/manuals/gcrypt/MPI-library.html
 *
 */

class Mpi
{
public:
  Mpi();
  virtual ~Mpi();
  Mpi(u_int8_t length);
  Mpi(const Mpi &src);
  Mpi(const u_int8_t * src, u_int32_t len);

  void operator=(const Mpi &src);
  void operator=(u_int32_t src);
  Mpi operator+(const Mpi &b) const;
  Mpi operator+(const u_int32_t &b) const;
  Mpi operator*(const u_int32_t n) const;
  Mpi operator/(const Mpi &b) const;

  Mpi operator^(const Mpi &b) const;

  Mpi mul2exp(u_int32_t e) const;     // value * 2^e

  /**
   * returns a new[] u_int8_t* buffer with the MPI value in the 
   * GCRYMPI_FMT_STD (2-complement stored without a length header).<br>
   * you have to delete it by hand with delete[]!
   * @param buf_len size of the new buffer that is returned
   * @return a byte buffer of size buf_len
   */
  u_int8_t *getNewBuf(size_t* written) const;
  std::string getHexDump() const;
  u_int32_t getLength() const;
 
protected:
  gcry_mpi_t val_;
};



#endif
