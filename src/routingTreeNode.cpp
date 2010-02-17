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

#include "routingTreeNode.h"

RoutingTreeNode::RoutingTreeNode():mux_(0),valid_(false)
{
  for(int i=0; i<256; i++) {
    nodes_[i]=NULL;
  }
}

void RoutingTreeNode::print(int level) const
{
  if(valid_) {
    std::cout << " -> " <<mux_ ;
  }
  std::cout  << std::endl;
  for(int i=0; i<256; i++) {
    if(nodes_[i]) {
      for(int l=0; l<level; l++) {
        std::cout << " ";
      }
      std::cout << (int) i;
      nodes_[i]->print(level+1);
    }
  }
}

RoutingTreeNode::~RoutingTreeNode()
{
  for(int i=0; i<256; i++)
    if(nodes_[i]) {
      delete nodes_[i];
    }
}
