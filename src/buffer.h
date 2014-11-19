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

#ifndef ANYTUN_buffer_h_INCLUDED
#define ANYTUN_buffer_h_INCLUDED

#include "datatypes.h"
#include <string>

class TunDevice;
class UDPPacketSource;

class Buffer
{
public:
  Buffer(bool allow_realloc = true);
  Buffer(uint32_t length, bool allow_realloc = true);
  Buffer(uint8_t* data, uint32_t length, bool allow_realloc = true);
  Buffer(std::string hex_data, bool allow_realloc = true);
  virtual ~Buffer();
  Buffer(const Buffer& src);
  void operator=(const Buffer& src);
  bool operator==(const Buffer& cmp) const;
  Buffer operator^(const Buffer& xor_by) const;

  uint32_t getLength() const;
  virtual void setLength(uint32_t new_length);
  uint8_t* getBuf();
  const uint8_t* getConstBuf() const;
  uint8_t& operator[](uint32_t index);
  uint8_t operator[](uint32_t index) const;
  std::string getHexDump() const;
  std::string getHexDumpOneLine() const;

  bool isReallocAllowed() const;

  operator uint8_t*();

protected:
  virtual void reinit() {};

  uint8_t* buf_;
  uint32_t length_;
  uint32_t real_length_;
  bool allow_realloc_;

  static const uint32_t OVER_SIZE_ = 100;
};

#endif
