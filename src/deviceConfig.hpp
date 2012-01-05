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

#ifndef ANYTUN_deviceConfig_hpp_INCLUDED
#define ANYTUN_deviceConfig_hpp_INCLUDED

#include "networkAddress.h"
#include <boost/asio.hpp>
#include "anytunError.h"

class TunDevice;

enum device_type_t { TYPE_UNDEF, TYPE_TUN, TYPE_TAP };

class DeviceConfig
{
public:
  DeviceConfig(std::string dev_name ,std::string dev_type, std::string ifcfg_addr, uint16_t ifcfg_prefix, uint16_t mtu) {
    mtu_ = mtu;
    type_ = TYPE_UNDEF;
#if !defined(_MSC_VER) && !defined(MINGW)
    if(dev_type != "") {
      if(!dev_type.compare(0,3,"tun")) {
        type_ = TYPE_TUN;
      } else if(!dev_type.compare(0,3,"tap")) {
        type_ = TYPE_TAP;
      }
    } else if(dev_name != "") {
      if(!dev_name.compare(0,3,"tun")) {
        type_ = TYPE_TUN;
      } else if(!dev_name.compare(0,3,"tap")) {
        type_ = TYPE_TAP;
      }
    }
#else
    if(dev_type == "") {
      AnytunError::throwErr() << "Device type must be specified on Windows";
    }

    if(dev_type == "tun") {
      type_ = TYPE_TUN;
    } else if(dev_type == "tap") {
      type_ = TYPE_TAP;
    }

    if(type_ == TYPE_TUN && ifcfg_addr == "") {
      AnytunError::throwErr() << "Device type tun requires ifconfig parameter (--ifconfig)";
    }
#endif

    if(ifcfg_addr != "") {
      addr_.setNetworkAddress(ipv4, ifcfg_addr.c_str());
    }
    prefix_ = ifcfg_prefix;
    uint32_t mask = 0;
    for(uint16_t i = 0; i < prefix_; ++i) {
      mask = mask >> 1;
      mask |= 0x80000000L;
    }
    netmask_.setNetworkAddress(boost::asio::ip::address_v4(mask));
  }

private:
  device_type_t type_;
  NetworkAddress addr_;
  NetworkAddress netmask_;
  uint16_t prefix_;
  uint16_t mtu_;

  friend class TunDevice;
};

#endif
