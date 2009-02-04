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
#include "log.h"
#define DEVICE_FILE_MAX 255

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_addr, std::string ifcfg_prefix) : conf_(dev_name, dev_type, ifcfg_addr, ifcfg_prefix, 1400)
{
  std::string device_file = "/dev/";
  bool dynamic = true;
  if(dev_name != "") {
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
    std::stringstream msg;
    if(dynamic)
      msg << "can't open device file dynamically: no unused node left";
    else
      msg << "can't open device file (" << device_file << "): " << LogErrno(errno);
    throw std::runtime_error(msg.str());
  }

  if(dynamic) {
    std::stringstream s;
    s << actual_name_;
    s << dev_id;
    actual_name_ = s.str();
  }
  else
    actual_name_ = dev_name;
  
  actual_node_ = device_file;

  init_post();

  if(ifcfg_addr != "")
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
  with_pi_ = true;
  if(conf_.type_ == TYPE_TAP)
    with_pi_ = false;
  
  struct tuninfo ti;  

  if (ioctl(fd_, TUNGIFINFO, &ti) < 0) {
    ::close(fd_);
    throw std::runtime_error("can't enable multicast for interface");
  }
  
  ti.flags |= IFF_MULTICAST;
  if(conf_.type_ == TYPE_TUN)
    ti.flags &= ~IFF_POINTOPOINT;
  
  if (ioctl(fd_, TUNSIFINFO, &ti) < 0) {
    ::close(fd_);
    throw std::runtime_error("can't enable multicast for interface");
  }
}

#elif defined(__GNUC__) && defined(__FreeBSD__)

void TunDevice::init_post()
{
  with_pi_ = true;
  if(conf_.type_ == TYPE_TAP)
    with_pi_ = false;

  int arg = 0;
  ioctl(fd_, TUNSLMODE, &arg);
  arg = 1;
  ioctl(fd_, TUNSIFHEAD, &arg);
}

#elif defined(__GNUC__) && defined(__NetBSD__)

void TunDevice::init_post()
{
  with_pi_ = false;

  int arg = IFF_POINTOPOINT|IFF_MULTICAST;
  ioctl(fd_, TUNSIFMODE, &arg);
  arg = 0;
  ioctl(fd_, TUNSLMODE, &arg);
}

#else
 #error This Device works just for OpenBSD, FreeBSD or NetBSD
#endif

int TunDevice::fix_return(int ret, size_t pi_length)
{
  if(ret < 0)
    return ret;

  return (static_cast<size_t>(ret) > type_length ? (ret - type_length) : 0);
}

int TunDevice::read(u_int8_t* buf, u_int32_t len)
{
  if(fd_ < 0)
    return -1;
  
  if(with_pi_) {
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
  
  if(!buf)
    return 0;

  if(with_pi_) {
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

void TunDevice::do_ifconfig()
{
  std::ostringstream command;
  command << "/sbin/ifconfig " << actual_name_ << " " << conf_.addr_.toString()
          << " netmask " << conf_.netmask_.toString() << " mtu " << conf_.mtu_;

  if(conf_.type_ == TYPE_TUN)
    command << " up";
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

  int result = system(command.str().c_str());
  if(result == -1)
    cLog.msg(Log::PRIO_ERR) << "Execution of ifconfig failed" << LogErrno(errno);
  else {
    if(WIFEXITED(result))
      cLog.msg(Log::PRIO_NOTICE) << "ifconfig returned " << WEXITSTATUS(result);  
    else if(WIFSIGNALED(result))
      cLog.msg(Log::PRIO_NOTICE) << "ifconfig terminated after signal " << WTERMSIG(result);
    else
      cLog.msg(Log::PRIO_ERR) << "Execution of ifconfig: unkown error";
  }

}
