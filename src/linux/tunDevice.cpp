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

#include <string.h>
#include <sstream>
#include <boost/assign.hpp>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"

#include "tunDevice.h"
#include "threadUtils.hpp"
#include "log.h"
#include "anytunError.h"
#include "sysExec.h"

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_addr, uint16_t ifcfg_prefix) : conf_(dev_name, dev_type, ifcfg_addr, ifcfg_prefix, 1400), sys_exec_(NULL)
{
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  if(conf_.type_ == TYPE_TUN) {
    ifr.ifr_flags = IFF_TUN;
    with_pi_ = true;
  } else if(conf_.type_ == TYPE_TAP) {
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    with_pi_ = false;
  } else {
    AnytunError::throwErr() << "unable to recognize type of device (tun or tap)";
  }

  if(dev_name != "") {
    strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ-1);
  }

  fd_ = ::open(DEFAULT_DEVICE, O_RDWR);
  if(fd_ < 0) {
    AnytunError::throwErr() << "can't open device file (" << DEFAULT_DEVICE  << "): " << AnytunErrno(errno);
  }

  if(!ioctl(fd_, TUNSETIFF, &ifr)) {
    actual_name_ = ifr.ifr_name;
  } else if(!ioctl(fd_, (('T' << 8) | 202), &ifr)) {
    actual_name_ = ifr.ifr_name;
  } else {
    ::close(fd_);
    AnytunError::throwErr() << "tun/tap device ioctl failed: " << AnytunErrno(errno);
  }
  actual_node_ = DEFAULT_DEVICE;

  if(ifcfg_addr != "") {
    do_ifconfig();
  }
}

TunDevice::~TunDevice()
{
  if(fd_ > 0) {
    ::close(fd_);
  }
}

int TunDevice::fix_return(int ret, size_t pi_length) const
{
  if(ret < 0) {
    return ret;
  }

  return (static_cast<size_t>(ret) > pi_length ? (ret - pi_length) : 0);
}

int TunDevice::read(uint8_t* buf, uint32_t len)
{
  if(fd_ < 0) {
    return -1;
  }

  if(with_pi_) {
    struct iovec iov[2];
    struct tun_pi tpi;

    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::readv(fd_, iov, 2), sizeof(tpi)));
  } else {
    return(::read(fd_, buf, len));
  }
}

int TunDevice::write(uint8_t* buf, uint32_t len)
{
  if(fd_ < 0) {
    return -1;
  }

  if(!buf) {
    return 0;
  }

  if(with_pi_) {
    struct iovec iov[2];
    struct tun_pi tpi;
    struct iphdr* hdr = reinterpret_cast<struct iphdr*>(buf);

    tpi.flags = 0;
    if(hdr->version == 4) {
      tpi.proto = htons(ETH_P_IP);
    } else {
      tpi.proto = htons(ETH_P_IPV6);
    }

    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::writev(fd_, iov, 2), sizeof(tpi)));
  } else {
    return(::write(fd_, buf, len));
  }
}

void TunDevice::init_post()
{
  // nothing to be done here
}

void TunDevice::do_ifconfig()
{
  std::ostringstream mtu_ss;
  mtu_ss << conf_.mtu_;
  StringVector args = boost::assign::list_of(actual_name_)(conf_.addr_.toString())("netmask")(conf_.netmask_.toString())("mtu")(mtu_ss.str());
  sys_exec_ = new SysExec("/sbin/ifconfig", args);
}

void TunDevice::waitUntilReady()
{
  if(sys_exec_) {
    SysExec::waitAndDestroy(sys_exec_);
  }
}
