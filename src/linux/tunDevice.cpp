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

#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"

#include "tunDevice.h"
#include "threadUtils.hpp"


TunDevice::TunDevice(const char* dev_name, const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp)
{
  fd_ = -1;
  type_ = TYPE_UNDEF;

	fd_ = ::open(DEFAULT_DEVICE, O_RDWR | O_NONBLOCK);

	if(fd_ < 0)
    throw std::runtime_error("can't init tun/tap device");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

// tun device
  ifr.ifr_flags = IFF_TUN;
  type_ = TYPE_TUN;

// tap device
//  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
//  type_ = TYPE_TAP;

	if(dev_name)
		strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

	if(!ioctl(fd_, TUNSETIFF, &ifr)) {
		actual_name_ = ifr.ifr_name;
	} else if(!ioctl(fd_, (('T' << 8) | 202), &ifr)) {
		actual_name_ = ifr.ifr_name;
	} else
    throw std::runtime_error("can't init tun/tap device");
}

TunDevice::~TunDevice()
{
  if(fd_ > 0)
    ::close(fd_);
}

short TunDevice::read(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;

  return ::read(fd_, buf, len);
}

int TunDevice::write(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;

  return ::write(fd_, buf, len);
}

const char* TunDevice::getActualName()
{
  return actual_name_.c_str();
}

u_int32_t TunDevice::getType()
{
  return type_;
}

const char* TunDevice::getTypeString()
{
  if(fd_ < 0)
    return NULL;

  switch(type_)
  {
  case TYPE_UNDEF: return "undef"; break;
  case TYPE_TUN: return "tun"; break;
  case TYPE_TAP: return "tap"; break;
  }
  return NULL;
}
