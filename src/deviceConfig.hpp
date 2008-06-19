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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DEVICE_CONFIG_HPP_
#define _DEVICE_CONFIG_HPP_

#include "networkAddress.h"
class TunDevice;

enum device_type_t { TYPE_UNDEF, TYPE_TUN, TYPE_TAP };

class DeviceConfig 
{
public:
  DeviceConfig(const char* dev_name ,const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp, u_int16_t mtu)
  {
    mtu_ = mtu;
    type_ = TYPE_UNDEF;
    if(dev_type) {
      if(!strncmp(dev_type, "tun", 3))
        type_ = TYPE_TUN;
      else if(!strncmp(dev_type, "tap", 3))
        type_ = TYPE_TAP;
    }
    else if(dev_name) {
      if(!strncmp(dev_name, "tun", 3))
        type_ = TYPE_TUN;
      else if(!strncmp(dev_name, "tap", 3))
        type_ = TYPE_TAP;
    }

    if(ifcfg_lp)
      local_.setNetworkAddress(ipv4, ifcfg_lp);
    if(ifcfg_rnmp)
      remote_netmask_.setNetworkAddress(ipv4, ifcfg_rnmp);
  }

private:
  device_type_t type_;
  NetworkAddress local_, remote_netmask_;
  u_int16_t mtu_;

  friend class TunDevice;
};

#endif
