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

#include "threadUtils.hpp"
#include "datatypes.h"
#include <cstring>
#include "seqWindow.h"

SeqWindowElement::SeqWindowElement()
{
  window_ = NULL;
  pos_ = 0;
  max_ = 0;
}

SeqWindowElement::~SeqWindowElement()
{
  if(window_) {
    delete[] window_;
  }
}

void SeqWindowElement::init(window_size_t w, seq_nr_t m)
{
  if(window_) {
    delete[] window_;
  }
  window_ = new uint8_t[w];
  memset(window_, 0, w);
  pos_ = 0;
  max_ = m;
  window_[pos_] = 1;
}

SeqWindow::SeqWindow(window_size_t w) : window_size_(w)
{
}

SeqWindow::~SeqWindow()
{
}

bool SeqWindow::checkAndAdd(sender_id_t sender, seq_nr_t seq_nr)
{
  Lock lock(mutex_);
  if(!window_size_) {
    return false;
  }

  SenderMap::iterator s = sender_.find(sender);
  if(s == sender_.end()) {
    sender_[sender].init(window_size_, seq_nr);
    return false;
  }

  int shifted = 0;
  if(s->second.max_ < window_size_) {
    s->second.max_ += SEQ_NR_MAX/2;
    seq_nr += SEQ_NR_MAX/2;
    shifted = 1;
  } else if(s->second.max_ > (SEQ_NR_MAX - window_size_)) {
    s->second.max_ -= SEQ_NR_MAX/2;
    seq_nr -= SEQ_NR_MAX/2;
    shifted = 2;
  }

  seq_nr_t min = s->second.max_ - window_size_ + 1;
  if(seq_nr < min || seq_nr == s->second.max_) {
    if(shifted == 1) {
      s->second.max_ -= SEQ_NR_MAX/2;
    } else if(shifted == 2) {
      s->second.max_ += SEQ_NR_MAX/2;
    }
    return true;
  }

  if(seq_nr > s->second.max_) {
    seq_nr_t diff = seq_nr - s->second.max_;
    if(diff >= window_size_) {
      diff = window_size_;
    }

    window_size_t new_pos = s->second.pos_ + diff;

    if(new_pos >= window_size_) {
      new_pos -= window_size_;

      if(s->second.pos_ < window_size_ - 1) {
        memset(&(s->second.window_[s->second.pos_ + 1]), 0, window_size_ - s->second.pos_ - 1);
      }

      memset(s->second.window_, 0, new_pos);
    } else {
      memset(&(s->second.window_[s->second.pos_ + 1]), 0, diff);
    }
    s->second.pos_ = new_pos;
    s->second.window_[s->second.pos_] = 1;
    s->second.max_ = seq_nr;

    if(shifted == 1) {
      s->second.max_ -= SEQ_NR_MAX/2;
    } else if(shifted == 2) {
      s->second.max_ += SEQ_NR_MAX/2;
    }

    return false;
  }

  seq_nr_t diff = s->second.max_ - seq_nr;
  window_size_t pos = diff > s->second.pos_ ? s->second.pos_ + window_size_ : s->second.pos_;
  pos -= diff;

  if(shifted == 1) {
    s->second.max_ -= SEQ_NR_MAX/2;
  } else if(shifted == 2) {
    s->second.max_ += SEQ_NR_MAX/2;
  }

  int ret = s->second.window_[pos];
  s->second.window_[pos] = 1;

  if(ret) {
    return true;
  }

  return false;
}

void SeqWindow::clear(sender_id_t sender)
{
  Lock lock(mutex_);
  sender_.erase(sender);
}

void SeqWindow::clear()
{
  Lock lock(mutex_);
  sender_.clear();
}
