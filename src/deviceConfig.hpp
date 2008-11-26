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

#ifndef _DEVICE_CONFIG_HPP_
#define _DEVICE_CONFIG_HPP_

#include "networkAddress.h"
class TunDevice;

enum device_type_t { TYPE_UNDEF, TYPE_TUN, TYPE_TAP };

class DeviceConfig 
{
public:
  DeviceConfig(std::string dev_name ,std::string dev_type, std::string ifcfg_lp, std::string ifcfg_rnmp, u_int16_t mtu)
  {
    mtu_ = mtu;
    type_ = TYPE_UNDEF;
    if(dev_type != "") {
      if(!dev_type.compare(0,3,"tun"))
        type_ = TYPE_TUN;
      else if (!dev_type.compare(0,3,"tap"))
        type_ = TYPE_TAP;
    }
    else if(dev_name != "") {
      if(!dev_name.compare(0,3,"tun"))
        type_ = TYPE_TUN;
      else if(!dev_name.compare(0,3,"tap"))
        type_ = TYPE_TAP;
    }

    if(ifcfg_lp != "")
      local_.setNetworkAddress(ipv4, ifcfg_lp.c_str());
    if(ifcfg_rnmp != "")
      remote_netmask_.setNetworkAddress(ipv4, ifcfg_rnmp.c_str());
  }

private:
  device_type_t type_;
  NetworkAddress local_, remote_netmask_;
  u_int16_t mtu_;

  friend class TunDevice;
};

#endif
