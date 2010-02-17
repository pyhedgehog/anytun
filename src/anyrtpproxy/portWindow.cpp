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

#include "portWindow.h"

PortWindow::PortWindow(u_int16_t start, u_int16_t end) : start_port_(start), end_port_(end)
{
}

PortWindow::~PortWindow()
{
}

PortWindow::PortSet::size_type PortWindow::getLength()
{
  Lock lock(mutex_);
  return ports_.size();
}

bool PortWindow::hasPort(u_int16_t port)
{
  Lock lock(mutex_);

  PortSet::const_iterator it=ports_.find(port);
  if(it == ports_.end()) {
    return false;
  }
  return true;
}

bool PortWindow::freePort(u_int16_t port)
{
  Lock lock(mutex_);

  PortSet::iterator it=ports_.find(port);
  if(it == ports_.end()) {
    return false;
  }
  ports_.erase(it);
  return true;
}

u_int16_t PortWindow::newPort()
{
  Lock lock(mutex_);
  u_int16_t port= start_port_;
  while(port<end_port_ && ports_.find(port) !=ports_.end()) {
    port++;
  }
  if(port>=end_port_) {
    return 0;
  }
  ports_.insert(port);
  return port;
}

void PortWindow::clear()
{
  Lock lock(mutex_);
  ports_.clear();
}

