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

#include <string.h>
#include <sstream>

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

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_lp, std::string ifcfg_rnmp) : conf_(dev_name, dev_type, ifcfg_lp, ifcfg_rnmp, 1400)
{
	fd_ = ::open(DEFAULT_DEVICE, O_RDWR);
	if(fd_ < 0) {
    std::stringstream msg;
    msg << "can't open device file (" << DEFAULT_DEVICE  << "): " << LogErrno(errno);
    throw std::runtime_error(msg.str());
  }

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

  if(conf_.type_ == TYPE_TUN) {
    ifr.ifr_flags = IFF_TUN;
    with_pi_ = true;
  } 
  else if(conf_.type_ == TYPE_TAP) {
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    with_pi_ = false;
  } 
  else
    throw std::runtime_error("unable to recognize type of device (tun or tap)");

	if(dev_name != "")
		strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);

	if(!ioctl(fd_, TUNSETIFF, &ifr)) {
		actual_name_ = ifr.ifr_name;
	} else if(!ioctl(fd_, (('T' << 8) | 202), &ifr)) {
		actual_name_ = ifr.ifr_name;
	} else {
    std::stringstream msg;
    msg << "tun/tap device ioctl failed: " << LogErrno(errno);
    throw std::runtime_error(msg.str());
  }

  if(ifcfg_lp != "" && ifcfg_rnmp != "")
    do_ifconfig();
}

TunDevice::~TunDevice()
{
  if(fd_ > 0)
    ::close(fd_);
}

int TunDevice::fix_return(int ret, size_t pi_length)
{
  if(ret < 0)
    return ret;

  return (static_cast<size_t>(ret) > pi_length ? (ret - pi_length) : 0);
}

int TunDevice::read(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;

  if(with_pi_)
  {
    struct iovec iov[2];
    struct tun_pi tpi;
    
    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::readv(fd_, iov, 2), sizeof(tpi)));
  }
  else
    return(::read(fd_, buf, len));
}

int TunDevice::write(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;

  if(with_pi_)
  {
    struct iovec iov[2];
    struct tun_pi tpi;
    struct iphdr *hdr = reinterpret_cast<struct iphdr *>(buf);
    
    tpi.flags = 0;
    if(hdr->version == 4)
      tpi.proto = htons(ETH_P_IP);
    else
      tpi.proto = htons(ETH_P_IPV6);
    
    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(fix_return(::writev(fd_, iov, 2), sizeof(tpi)));
  }
  else
    return(::write(fd_, buf, len));
}

void TunDevice::init_post()
{
// nothing to be done here
}

void TunDevice::do_ifconfig()
{
  std::ostringstream command;
  command << "/sbin/ifconfig " << actual_name_ << " " << conf_.local_.toString();

  if(conf_.type_ == TYPE_TUN)
    command << " pointopoint ";
  else
    command << " netmask ";

  command << conf_.remote_netmask_.toString() << " mtu " << conf_.mtu_;

  int result = system(command.str().c_str());
  if(result == -1)
    cLog.msg(Log::PRIO_ERR) << "Execution of ifconfig failed";
  else
    cLog.msg(Log::PRIO_NOTICE) << "ifconfig returned " << WEXITSTATUS(result);
}
