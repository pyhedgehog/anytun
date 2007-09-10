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

#include "threadUtils.hpp"
#include "datatypes.h"

#include "seqWindow.h"

SeqWindow::SeqWindow(window_size_t w) : window_size_(w)
{
}

SeqWindow::~SeqWindow()
{
}

SeqWindow::SeqDeque::size_type SeqWindow::getLength(sender_id_t sender)
{
  Lock lock(mutex_);
  SenderMap::const_iterator s = sender_.find(sender);
  if(s == sender_.end())
    return 0;

  return s->second.size();
}

bool SeqWindow::hasSeqNr(sender_id_t sender, seq_nr_t seq)
{
  Lock lock(mutex_);
  if (!window_size_)
    return false;
  SenderMap::const_iterator s = sender_.find(sender);
  if(s == sender_.end())
    return false;

  SeqDeque::const_iterator it;
  for(it = s->second.begin(); it != s->second.end(); it++)
    if(*it == seq)
      return true;
  
  return false;
}

void SeqWindow::addSeqNr(sender_id_t sender, seq_nr_t seq)
{
  Lock lock(mutex_);
  if(sender_[sender].size() >= window_size_)
    sender_[sender].pop_front();
  sender_[sender].push_back(seq);
}

void SeqWindow::clear(sender_id_t sender)
{
  Lock lock(mutex_);
  sender_[sender].clear();
  sender_.erase(sender);
}

void SeqWindow::clear()
{
  Lock lock(mutex_);
  sender_.clear();
}
