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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <sstream>

#include "tunDevice.h"
#include "threadUtils.hpp"
#define DEVICE_FILE_MAX 255

#include <iostream>

TunDevice::TunDevice(const char* dev_name, const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp) : conf_(dev_name, dev_type, ifcfg_lp, ifcfg_rnmp, 1400)
{
  std::string device_file = "/dev/";
  bool dynamic = true;
  if(dev_name) {
    device_file.append(dev_name);
    dynamic = false;
  }
  else if(conf_.type_ == TYPE_TUN) {
    device_file.append("tun");
    actual_name_ = "tun";
  }
  else if(conf_.type_ == TYPE_TAP) {
    device_file.append("tap");
    actual_name_ = "tap";
  }
  else
    throw std::runtime_error("unable to recognize type of device (tun or tap)");

  u_int32_t dev_id=0;
  if(dynamic) {
    for(; dev_id <= DEVICE_FILE_MAX; ++dev_id) {
      std::ostringstream ds;
      ds << device_file;
      ds << dev_id;
      fd_ = ::open(ds.str().c_str(), O_RDWR);
      if(fd_ >= 0)
        break;
    }
  }
  else
    fd_ = ::open(device_file.c_str(), O_RDWR);

  if(fd_ < 0) {
    std::string msg;
    if(dynamic)
      msg = "can't open device file dynamically: no unused node left";
    else {
      msg = "can't open device file (";
      msg.append(device_file);
      msg.append("): ");
      char buf[STERROR_TEXT_MAX];
      buf[0] = 0;
      strerror_r(errno, buf, STERROR_TEXT_MAX);
      msg.append(buf);
    }
    throw std::runtime_error(msg);
  }

  if(dynamic) {
    std::stringstream s;
    s << actual_name_;
    s << dev_id;
    actual_name_ = s.str();
  }
  else
    actual_name_ = dev_name;
  
  init_post();

  if(ifcfg_lp && ifcfg_rnmp)
    do_ifconfig();
}

TunDevice::~TunDevice()
{
  if(fd_ > 0)
    ::close(fd_);
}

#if defined(__GNUC__) && defined(__OpenBSD__)

void TunDevice::init_post()
{
  with_type_ = true;
  if(conf_.type_ == TYPE_TAP)
    with_type_ = false;
  
  struct tuninfo ti;  

  if (ioctl(fd_, TUNGIFINFO, &ti) < 0)
    throw std::runtime_error("can't enable multicast for interface");
  
  ti.flags |= IFF_MULTICAST;
  
  if (ioctl(fd_, TUNSIFINFO, &ti) < 0)
    throw std::runtime_error("can't enable multicast for interface");
}

#elif defined(__GNUC__) && defined(__FreeBSD__)

void TunDevice::init_post()
{
  with_type_ = true;
  if(conf_.type_ == TYPE_TAP)
    with_type_ = false;

  int arg = 0;
  ioctl(fd_, TUNSLMODE, &arg);
  arg = 1;
  ioctl(fd_, TUNSIFHEAD, &arg);
}

#elif defined(__GNUC__) && defined(__NetBSD__)

void TunDevice::init_post()
{
  with_type_ = false;

  int arg = IFF_POINTOPOINT|IFF_MULTICAST;
  ioctl(fd_, TUNSIFMODE, &arg);
  arg = 0;
  ioctl(fd_, TUNSLMODE, &arg);
}

#else
 #error This Device works just for OpenBSD, FreeBSD or NetBSD
#endif

int TunDevice::fix_return(int ret, size_t type_length)
{
  if(ret < 0)
    return ret;

  return (static_cast<size_t>(ret) > type_length ? (ret - type_length) : 0);
}

short TunDevice::read(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;
  
  if(with_type_) {
    struct iovec iov[2];
    u_int32_t type;
    
    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::readv(fd_, iov, 2), sizeof(type)));
  }
  else
    return(::read(fd_, buf, len));
}

int TunDevice::write(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;
  
  if(with_type_) {
    struct iovec iov[2];
    u_int32_t type;
    struct ip *hdr = reinterpret_cast<struct ip*>(buf);
    
    type = 0;
    if(hdr->ip_v == 4)
      type = htonl(AF_INET);
    else
      type = htonl(AF_INET6);
    
    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::writev(fd_, iov, 2), sizeof(type)));
  }
  else
    return(::write(fd_, buf, len));
}

const char* TunDevice::getActualName()
{
  return actual_name_.c_str();
}

device_type_t TunDevice::getType()
{
  return conf_.type_;
}

const char* TunDevice::getTypeString()
{
  if(fd_ < 0)
    return NULL;

  switch(conf_.type_)
  {
  case TYPE_UNDEF: return "undef"; break;
  case TYPE_TUN: return "tun"; break;
  case TYPE_TAP: return "tap"; break;
  }
  return NULL;
}

void TunDevice::do_ifconfig()
{
  std::ostringstream command;
  command << "/sbin/ifconfig " << actual_name_ << " " << conf_.local_.toString();

  if(conf_.type_ == TYPE_TAP)
    command << " netmask ";
  else
    command << " ";

  command << conf_.remote_netmask_.toString() << " mtu " << conf_.mtu_;

  if(conf_.type_ == TYPE_TUN)
    command << " netmask 255.255.255.255 up";
  else {
#if defined(__GNUC__) && defined(__OpenBSD__)
    command << " link0";
#elif defined(__GNUC__) && defined(__FreeBSD__)
    command << " up";
#elif defined(__GNUC__) && defined(__NetBSD__)
    command << "";
#else
 #error This Device works just for OpenBSD, FreeBSD or NetBSD
#endif
  }

  system(command.str().c_str());
}
