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

#include <cstring>
#include <stdexcept>
#include <string>
#include <sstream>
#include <iostream>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include "datatypes.h"
#include "buffer.h"

Buffer::Buffer(bool allow_realloc) : buf_(0), length_(0), real_length_(0), allow_realloc_(allow_realloc)
{
}

Buffer::Buffer(uint32_t length, bool allow_realloc) : length_(length), real_length_(length_ + Buffer::OVER_SIZE_),
  allow_realloc_(allow_realloc)
{
  buf_ = new uint8_t[real_length_];
  if(!buf_) {
    length_ = 0;
    real_length_ = 0;
    throw std::bad_alloc();
  }
  std::memset(buf_, 0, real_length_);
}

Buffer::Buffer(uint8_t* data, uint32_t length, bool allow_realloc) : length_(length), real_length_(length + Buffer::OVER_SIZE_),
  allow_realloc_(allow_realloc)
{
  if(!data) {
    length_ = 0;
    real_length_ = 0;
    return;
  }

  buf_ = new uint8_t[real_length_];
  if(!buf_) {
    length_ = 0;
    real_length_ = 0;
    throw std::bad_alloc();
  }
  std::memcpy(buf_, data, length_);
}

Buffer::Buffer(std::string hex_data, bool allow_realloc) : length_(static_cast<uint32_t>(hex_data.size())/2),
  real_length_(length_ + Buffer::OVER_SIZE_),
  allow_realloc_(allow_realloc)
{
  buf_ = new uint8_t[real_length_];
  if(!buf_) {
    length_ = 0;
    real_length_ = 0;
    throw std::bad_alloc();
  }

  for(uint32_t i=0; i<length_; ++i) {
    uint32_t tmp;
    std::istringstream ss(std::string(hex_data.c_str(), i*2, 2));
    if(!(ss >> std::hex >> tmp)) { tmp = 0; }
    buf_[i] = static_cast<uint8_t>(tmp);
  }
}

Buffer::~Buffer()
{
  if(buf_) {
    delete[] buf_;
  }
}

Buffer::Buffer(const Buffer& src) : length_(src.length_), real_length_(src.real_length_), allow_realloc_(src.allow_realloc_)
{
  buf_ = new uint8_t[real_length_];
  if(!buf_) {
    length_ = 0;
    real_length_ = 0;
    throw std::bad_alloc();
  }
  std::memcpy(buf_, src.buf_, length_);
}

void Buffer::operator=(const Buffer& src)
{
  if(buf_) {
    delete[] buf_;
  }

  length_ = src.length_;
  real_length_ = src.real_length_;
  allow_realloc_ = src.allow_realloc_;

  buf_ = new uint8_t[real_length_];
  if(!buf_) {
    length_ = 0;
    real_length_ = 0;
    throw std::bad_alloc();
  }
  std::memcpy(buf_, src.buf_, length_);
}

bool Buffer::operator==(const Buffer& cmp) const
{
  if(length_ != cmp.length_) {
    return false;
  }

  if(!std::memcmp(buf_, cmp.buf_, length_)) {
    return true;
  }

  return false;
}

Buffer Buffer::operator^(const Buffer& xor_by) const
{
  uint32_t res_length = (xor_by.length_ > length_) ? xor_by.length_ : length_;
  uint32_t min_length = (xor_by.length_ < length_) ? xor_by.length_ : length_;
  Buffer res(res_length);

  for(uint32_t index = 0; index < min_length; index++) {
    res[index] = buf_[index] ^ xor_by[index];
  }

  return res;
}

uint32_t Buffer::getLength() const
{
  return length_;
}

void Buffer::setLength(uint32_t new_length)
{
  if(new_length == length_) {
    return;
  }

  if(new_length > real_length_) {
    if(!allow_realloc_) {
      throw std::out_of_range("buffer::setLength() - reallocation not allowed for this Buffer");
    }

    uint8_t* old_buf = buf_;
    uint32_t old_length = length_;

    length_ = new_length;
    real_length_ = length_ + Buffer::OVER_SIZE_;

    buf_ = new uint8_t[real_length_];
    if(!buf_) {
      length_ = 0;
      real_length_ = 0;
      if(old_buf) {
        delete[] old_buf;
      }

      throw std::bad_alloc();
    }
    std::memcpy(buf_, old_buf, old_length);

    if(old_buf) {
      delete[] old_buf;
    }

    old_buf = &buf_[old_length];
    std::memset(old_buf, 0, real_length_ - old_length);
  } else {
    length_ = new_length;
  }

  reinit();
}


uint8_t* Buffer::getBuf()
{
  return buf_;
}

uint8_t& Buffer::operator[](uint32_t index)
{
  if(index >= length_) {
    throw std::out_of_range("buffer::operator[]");
  }

  return buf_[index];
}

uint8_t Buffer::operator[](uint32_t index) const
{
  if(index >= length_) {
    throw std::out_of_range("buffer::operator[] const");
  }

  return buf_[index];
}

Buffer::operator uint8_t*()
{
  return buf_;
}

std::string Buffer::getHexDump() const
{
  std::stringstream ss;
  ss << "Length=" << length_ << std::endl << std::hex << std::uppercase;
  for(uint32_t index = 0; index < length_; index++) {
    ss << std::setw(2) << std::setfill('0') << uint32_t(buf_[index]) << " ";
    if(!((index+1) % 16)) {
      ss << std::endl;
      continue;
    }
    if(!((index+1) % 8)) {
      ss << " ";
    }
  }
  return ss.str();
}

std::string Buffer::getHexDumpOneLine() const
{
  std::stringstream ss;
  ss << length_ << " Bytes,'" << std::hex << std::uppercase;
  for(uint32_t index = 0; index < length_; index++) {
    ss << std::setw(2) << std::setfill('0') << uint32_t(buf_[index]);
  }
  ss << "'";
  return ss.str();
}

bool Buffer::isReallocAllowed() const
{
  return allow_realloc_;
}
