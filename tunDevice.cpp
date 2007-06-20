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

#include <stdexcept>
#include <poll.h>

extern "C" {
#include "openvpn/config.h"
#include "openvpn/syshead.h"
#include "openvpn/tun.h"
}

#include "tunDevice.h"
#include "threadUtils.hpp"


TunDevice::TunDevice(const char* dev_name, const char* ifcfg_lp, const char* ifcfg_rnmp)
{
  dev_ = NULL;

// init_tun (const char *dev,       /* --dev option */
// 	         const char *dev_type,  /* --dev-type option */
// 	         const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
// 	         const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
// 	         in_addr_t local_public,
// 	         in_addr_t remote_public,
// 	         const bool strict_warn,
// 	         struct env_set *es)

// init_tun_post (struct tuntap *tt,
// 	              const struct frame *frame,
// 	              const struct tuntap_options *options)

// open_tun (const char *dev,
//           const char *dev_type,
//           const char *dev_node, 
//           bool ipv6, 
//           struct tuntap *tt)

// -------------------------------------------

// c->c1.tuntap = init_tun (c->options.dev,
//                          c->options.dev_type,
//                          c->options.ifconfig_local,
//                          c->options.ifconfig_remote_netmask,
//                          addr_host (&c->c1.link_socket_addr.local),
//                          addr_host (&c->c1.link_socket_addr.remote),
//                          !c->options.ifconfig_nowarn,
//                          c->c2.es);
  
// init_tun_post (c->c1.tuntap,
//                &c->c2.frame,
//                &c->options.tuntap_options);

// open_tun (c->options.dev, 
//           c->options.dev_type, 
//           c->options.dev_node,
//           c->options.tun_ipv6,
//           c->c1.tuntap);


  
  in_addr_t lp, rp;

//   lp = inet_addr("192.168.198.1");
//   rp = inet_addr("192.168.199.1");

  dev_ = init_tun(dev_name, NULL, ifcfg_lp, ifcfg_rnmp, lp, rp, 0, NULL);
  struct frame frame; // just for win32
  struct tuntap_options options; // win32 & linux
  options.txqueuelen = 100; // just for linux
  init_tun_post(dev_, &frame, &options);
  if(!dev_)
    throw std::runtime_error("can't init tun/tap device");

  open_tun (dev_name, NULL, NULL, false, dev_);
  do_ifconfig(dev_, dev_->actual_name, 1000, NULL);
}

TunDevice::~TunDevice()
{
  if(dev_)
    close_tun(dev_);
}

short TunDevice::read(Buffer& buf)
{
  if(!dev_)
    return -1;

  struct pollfd pfd[1];
  pfd[0].fd = tun_event_handle(dev_);
  pfd[0].events = POLLIN | POLLPRI;
  pfd[0].revents = 0;
  poll(pfd, 1, -1);
  Lock lock(io_mutex_);
  return read_tun(dev_, buf, buf.getLength());
}

int TunDevice::write(Buffer& buf)
{
  if(!dev_)
    return -1;
  Lock lock(io_mutex_);
  return write_tun(dev_, buf, buf.getLength());
}

char* TunDevice::getActualName()
{
  if(!dev_)
    return NULL;

  return dev_->actual_name;
}

char* TunDevice::getType()
{
  if(!dev_)
    return NULL;
  
  switch(dev_->type)
  {
  case DEV_TYPE_UNDEF: return "undef"; break;
  case DEV_TYPE_TUN: return "tun"; break;
  case DEV_TYPE_TAP: return "tap"; break;
  }
  return NULL;
}
