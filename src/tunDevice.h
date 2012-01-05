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

#ifndef ANYTUN_tunDevice_h_INCLUDED
#define ANYTUN_tunDevice_h_INCLUDED

#include "buffer.h"
#include "deviceConfig.hpp"
#include "threadUtils.hpp"
#if !defined(_MSC_VER) && !defined(MINGW)
#include "sysExec.h"
#else
#include <windows.h>
#endif

class TunDevice
{
public:
  TunDevice(std::string dev,std::string dev_type, std::string ifcfg_addr, uint16_t ifcfg_prefix);
  ~TunDevice();

  int read(uint8_t* buf, uint32_t len);
  int write(uint8_t* buf, uint32_t len);

  const char* getActualName() const { return actual_name_.c_str(); }
  const char* getActualNode() const { return actual_node_.c_str(); }
  device_type_t getType() const { return conf_.type_; }
  void waitUntilReady();
  const char* getTypeString() const {
#if !defined(_MSC_VER) && !defined(MINGW)
    if(fd_ < 0)
#else
    if(handle_ == INVALID_HANDLE_VALUE)
#endif
      return "";

    switch(conf_.type_) {
    case TYPE_UNDEF:
      return "undef";
      break;
    case TYPE_TUN:
      return "tun";
      break;
    case TYPE_TAP:
      return "tap";
      break;
    }
    return "";
  }

private:
  void operator=(const TunDevice& src);
  TunDevice(const TunDevice& src);

  void init_post();
  void do_ifconfig();
  int fix_return(int ret, size_t pi_length) const;

#if !defined(_MSC_VER) && !defined(MINGW)
  int fd_;
#else
  bool getAdapter(std::string const& dev_name);
  DWORD performIoControl(DWORD controlCode, LPVOID inBuffer, DWORD inBufferSize,
                         LPVOID outBuffer, DWORD outBufferSize);
  HANDLE handle_;
  OVERLAPPED roverlapped_, woverlapped_;
#endif

  DeviceConfig conf_;
#if !defined(_MSC_VER) && !defined(MINGW)
  SysExec* sys_exec_;
#endif
  bool with_pi_;
  std::string actual_name_;
  std::string actual_node_;
};

#endif
