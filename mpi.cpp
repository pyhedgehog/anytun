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

#include <iostream>

Mpi::Mpi() : val_(NULL)
{
  val_ = gcry_mpi_set_ui(NULL, 0);
  if(!val_)
    throw std::bad_alloc();
}

Mpi::Mpi(u_int8_t length) : val_(NULL)
{
  val_ = gcry_mpi_new(length);
  if(!val_)
    throw std::bad_alloc();
}

Mpi::Mpi(const Mpi &src) : val_(NULL)
{
  val_ = gcry_mpi_copy(src.val_);
  if(!val_)
    throw std::bad_alloc();
}

Mpi::Mpi(const u_int8_t* src, u_int32_t len) : val_(NULL)
{
  u_int8_t* src_cpy = new u_int8_t[len+1];
  if(!src_cpy)
    throw std::bad_alloc();

  u_int8_t* buf = src_cpy;
  u_int32_t buf_len = len;
  if(src[0] & 0x80) // this would be a negative number, scan can't handle this :(
  {
    src_cpy[0] = 0;
    buf++;
    buf_len++;
  }
  std::memcpy(buf, src, len);

  gcry_mpi_scan( &val_, GCRYMPI_FMT_STD, src_cpy, buf_len, NULL );
  delete[] src_cpy;
  if(!val_)
    throw std::bad_alloc();
}

Mpi::~Mpi()
{
  gcry_mpi_release( val_ ); 
}


void Mpi::operator=(const Mpi &src)
{
  gcry_mpi_release( val_ ); 
  val_ = gcry_mpi_copy(src.val_);
  if(!val_)
    throw std::bad_alloc();
}

void Mpi::operator=(const u_int32_t src)
{
  gcry_mpi_release( val_ ); 
  val_ = gcry_mpi_set_ui(NULL, src);
  if(!val_)
    throw std::bad_alloc();
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

//TODO: problem, seems as gcry_mpi_(a)print doesn't work for mpi values of '0'
u_int8_t* Mpi::getNewBuf(u_int32_t* written) const
{
  u_int8_t* res_cpy;
  gcry_mpi_aprint( GCRYMPI_FMT_STD, &res_cpy, written, val_ );
  if(!res_cpy)
    throw std::bad_alloc();
    
  u_int8_t* buf = res_cpy;
  if(*written > 1 && ! (res_cpy[0])) // positive number with highestBit set
  {
    buf++;
    (*written)--;
  }

  u_int8_t* res = new u_int8_t[*written];
  if(!res)
    throw std::bad_alloc();

  std::memcpy(res, buf, *written);

  gcry_free(res_cpy);

  return res;
}

//TODO: why does this not work ?????
std::string Mpi::getHexDump() const
{
//   u_int8_t *buf;
//   u_int32_t len;
//   gcry_mpi_aprint( GCRYMPI_FMT_HEX, &buf, &len, val_ );
//   std::string res(buf, len);
//   delete[] buf;

  gcry_mpi_dump( val_ );
  std::string res("\n");
  return res;
}

u_int32_t Mpi::getLength() const
{
  return gcry_mpi_get_nbits( val_ );
}
