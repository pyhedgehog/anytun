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

#include <stdexcept>
#include <string>
#include <iostream>
#include <cstdio>

#include "datatypes.h"
#include "buffer.h"

Buffer::Buffer() : buf_(0), length_(0)
{  
}

Buffer::Buffer(u_int32_t length) : length_(length)
{
  buf_ = new u_int8_t[length_];
  if(buf_)
    std::memset(buf_, 0, length_);
  else 
    length_ = 0;
}

Buffer::Buffer(u_int8_t* data, u_int32_t length) : length_(length)
{
  buf_ = new u_int8_t[length_];
  if(buf_)
    std::memcpy(buf_, data, length_);
  else 
    length_ = 0;
}

Buffer::~Buffer()
{
  if(buf_)
    delete[] buf_;
}

Buffer::Buffer(const Buffer &src) : length_(src.length_)
{
  buf_ = new u_int8_t[length_];
  if(buf_)
    std::memcpy(buf_, src.buf_, length_);
  else 
    length_ = 0;
}

void Buffer::operator=(const Buffer &src)
{
  if(buf_)
    delete[] buf_;
 
  length_ = src.length_;
 
  buf_ = new u_int8_t[length_];
  if(buf_)
    std::memcpy(buf_, src.buf_, length_);
  else
    length_ = 0;
}

u_int32_t Buffer::resizeFront(u_int32_t new_length)
{
  if(length_ == new_length)
    return length_;

  u_int8_t *tmp = new u_int8_t[new_length];
  if(!tmp)
    return length_;

  if(buf_)
  {
    u_int8_t *src=buf_, *dest=tmp;
    if(length_ < new_length)
      dest = &dest[new_length - length_];
    else
      src = &src[length_ - new_length];
    u_int32_t len = length_ < new_length ? length_ : new_length;
    std::memcpy(dest, src, len);
    delete[] buf_;
  }

  length_ = new_length;
  buf_ = tmp;
  return length_;
}

u_int32_t Buffer::resizeBack(u_int32_t new_length)
{
  if(length_ == new_length)
    return length_;

  u_int8_t *tmp = new u_int8_t[new_length];
  if(!tmp)
    return length_;

  if(buf_)
  {
    u_int32_t len = length_ < new_length ? length_ : new_length;
    std::memcpy(tmp, buf_, len);
    delete[] buf_;
  }

  length_ = new_length;
  buf_ = tmp;
  return length_;
}

u_int32_t Buffer::getLength() const
{
  return length_;
}

u_int8_t* Buffer::getBuf()
{
  return buf_;
}

u_int8_t& Buffer::operator[](u_int32_t index)
{
  if(index >= length_)
    throw std::out_of_range("buffer::operator[]");

  return buf_[index];
}

u_int8_t Buffer::operator[](u_int32_t index) const
{
  if(index >= length_)
    throw std::out_of_range("buffer::operator[] const");

  return buf_[index];
}

Buffer::operator u_int8_t*() // just for write/read tun
{
  return buf_;
}

std::ostream& operator<<(std::ostream& output, const Buffer &src)
{
  char buf[10];

  for( u_int32_t index = 0; index < src.getLength(); index++ )
  {
    std::sprintf(buf, "%#x", src[index]);
    output << buf << " ";
  }
  
  return output;
}
