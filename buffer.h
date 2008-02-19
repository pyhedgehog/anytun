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

#ifndef _BUFFER_H_
#define _BUFFER_H_

#include "datatypes.h"
#include <string>

class TunDevice;
class UDPPacketSource;

class Buffer
{
public:
  Buffer();
  Buffer(u_int32_t length);
  Buffer(u_int8_t* data, u_int32_t length);
  virtual ~Buffer();
  Buffer(const Buffer &src);
  void operator=(const Buffer &src);
  bool operator==(const Buffer &cmp) const;

  // math operations to calculate IVs and keys
  virtual Buffer operator^(const Buffer &xor_by) const;
  virtual Buffer leftByteShift(u_int32_t width) const;
  virtual Buffer rightByteShift(u_int32_t width) const;

  u_int32_t resizeFront(u_int32_t new_length);
  u_int32_t resizeBack(u_int32_t new_length);
  u_int32_t getLength() const;
  u_int8_t* getBuf();
  u_int8_t& operator[](u_int32_t index);
  u_int8_t operator[](u_int32_t index) const;
  std::string getHexDump() const;

  operator u_int8_t*(); // just for write/read tun and packetSource
protected:
  friend class TunDevice;
  friend class UDPPacketSource;
  friend class AesIcmCipher;
  friend class KeyDerivation;   //
  friend class Mpi;

  u_int8_t *buf_;
  u_int32_t length_;
};

#endif
