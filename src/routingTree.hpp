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

#ifndef __ROUTING_TREE_
#define __ROUTING_TREE_

#include "anytunError.hpp"

class RoutingTree {

public:
  template <class BinaryType>
  static void walk(BinaryType bytes ,RoutingTreeNode * node,u_int8_t length,u_int16_t mux)
  {
    for (int i=0; i<(length/8); i++)
    {
      if (!node->nodes_[bytes[i]])
        node->nodes_[bytes[i]] = new RoutingTreeNode;
      node=node->nodes_[bytes[i]];
    }
    if (length%8)
    {
      unsigned char idx=0xff;
      idx <<=8-(length%8);
      idx &= bytes[length/8];
      unsigned char maxidx=0xff;
      maxidx>>=(length%8);
      maxidx|=idx;
      for (unsigned char i=idx; i<=maxidx; i++)
      {
        if (!node->nodes_[i])
          node->nodes_[i] = new RoutingTreeNode;
        node->nodes_[i]->valid_=true;
        node->nodes_[i]->mux_=mux;
      }
    } else {
      node->valid_=true;
      node->mux_=mux;
    }
  }
  
  template <class BinaryType>
  static u_int16_t find(BinaryType bytes ,RoutingTreeNode & root )
  {
    bool valid=0;
    u_int16_t mux=0;
    RoutingTreeNode * node = &root;
    if (root.valid_)
    {
      mux=root.mux_;
      valid=1;
    }
    for (size_t level=0;level<bytes.size();level++)
    {
      if (node->nodes_[bytes[level]])
      {
        node=node->nodes_[bytes[level]];
        if(node->valid_)
        {
          mux=node->mux_;
          valid=1;
        }
      } else {
        break;
      }
    }
    if(!valid)
      AnytunError::throwErr() << "no route";
    return mux;
  }

};

#endif
  
  
