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

#ifndef _TUNDEVICE_H_
#define _TUNDEVICE_H_

#include "buffer.h"
#include "deviceConfig.hpp"
#include "threadUtils.hpp"

class TunDevice
{
public:
  TunDevice(const char* dev,const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp);
  ~TunDevice();
  
  int read(u_int8_t* buf, u_int32_t len);
  int write(u_int8_t* buf, u_int32_t len);

  const char* getActualName();
  device_type_t getType();
  const char* getTypeString();

private:
  void operator=(const TunDevice &src);
  TunDevice(const TunDevice &src);

  void do_ifconfig();
  int fix_return(int ret, size_t pi_length);

  int fd_;
  DeviceConfig conf_;
  bool with_pi_;
  std::string actual_name_;
};

#endif
