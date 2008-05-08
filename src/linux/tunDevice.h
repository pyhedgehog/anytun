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

#ifndef _TUNDEVICE_H_
#define _TUNDEVICE_H_

#include "buffer.h"
#include "threadUtils.hpp"

class TunDevice
{
public:
  static const u_int32_t TYPE_UNDEF = 0;
  static const u_int32_t TYPE_TUN = 1;
  static const u_int32_t TYPE_TAP = 2;

  TunDevice(const char* dev,const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp);
  ~TunDevice();
  
  short read(u_int8_t* buf, u_int32_t len);
  int write(u_int8_t* buf, u_int32_t len);

  const char* getActualName();
  u_int32_t getType();
  const char* getTypeString();

private:
  void operator=(const TunDevice &src);
  TunDevice(const TunDevice &src);

  int fd_;
  u_int32_t type_;
  std::string actual_name_;
};

#endif
