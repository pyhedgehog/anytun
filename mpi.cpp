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

#include "mpi.h"

#include "datatypes.h"
#include "cipher.h"

#include <stdexcept>
#include <gcrypt.h>


Mpi::Mpi()
{
  val_ = gcry_mpi_new(1);
}

Mpi::Mpi(u_int8_t length)
{
  val_ = gcry_mpi_new(length);
}

Mpi::Mpi(const Mpi &src)
{
  val_ = gcry_mpi_copy(src.val_);
}

Mpi::Mpi(const u_int8_t * src, u_int32_t len)
{
  gcry_mpi_scan( &val_, GCRYMPI_FMT_STD, src, len, NULL );
}

Mpi::~Mpi()
{
  gcry_mpi_release( val_ );
}


void Mpi::operator=(const Mpi &src)
{
  val_ = gcry_mpi_copy(src.val_);
}

void Mpi::operator=(const u_int32_t src)
{
  gcry_mpi_set_ui(val_, src);
}

Mpi Mpi::operator+(const Mpi &b) const
{
  Mpi res;
  gcry_mpi_add(res.val_, val_, b.val_);
  return res;
}

Mpi Mpi::operator+(const u_int32_t &b) const
{
  Mpi res;
  gcry_mpi_add_ui(res.val_, val_, b);
  return res;
}

Mpi Mpi::operator*(const u_int32_t n) const
{
  Mpi res;
  gcry_mpi_mul_ui(res.val_, val_, n);
  return res;
}

Mpi Mpi::operator/(const Mpi &b) const
{
  Mpi res;
  gcry_mpi_div(res.val_, NULL, val_, b.val_, 0);
  return res;
}

//TODO: this is outstandingly ugly!!!!!!!!
Mpi Mpi::operator^(const Mpi &b) const
{
  u_int32_t a_len = gcry_mpi_get_nbits(val_);
  u_int32_t b_len = gcry_mpi_get_nbits(b.val_);

  Mpi res = (a_len >= b_len) ? Mpi(*this) : Mpi(b);

  for(u_int32_t i=0; i<a_len && i<b_len; i++) {
    if(gcry_mpi_test_bit(val_, i) ^ gcry_mpi_test_bit(b.val_, i))
      gcry_mpi_set_bit(res.val_, i);
    else
      gcry_mpi_clear_bit(res.val_, i);
  }
  return res;
}

Mpi Mpi::mul2exp(u_int32_t e) const
{
  Mpi res;
  gcry_mpi_mul_2exp( res.val_, val_, e );
  return res;
}

u_int8_t* Mpi::getNewBuf(u_int32_t buf_len) const
{
  // u_int32_t len = 0;
  u_int32_t written = 0;

  u_int8_t *res = NULL;
  res = new u_int8_t[buf_len];
  std::memset(res, 0, buf_len);

  //  len = gcry_mpi_get_nbits( val_ );
  //  if( len%8 == 0 )
  //    len = len/8;
  //  else
  //    len = (len/8)+1;

  gcry_mpi_print( GCRYMPI_FMT_STD, res, buf_len, &written, val_ );
  return res;
}

//TODO: why does this not work ?????
std::string Mpi::getHexDump() const
{
//   u_int8_t *buf;
//   u_int32_t len;
//   gcry_mpi_aprint( GCRYMPI_FMT_HEX, &buf, &len, val_ );
//   std::string res(buf, len);
  
  gcry_mpi_dump( val_ );
  std::string res("\n");
  return res;
}

u_int32_t Mpi::getLength() const
{
  return gcry_mpi_get_nbits( val_ );
}
