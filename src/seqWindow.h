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

#ifndef ANYTUN_seqWindow_h_INCLUDED
#define ANYTUN_seqWindow_h_INCLUDED

#include <map>
#include <deque>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include "threadUtils.hpp"
#include "datatypes.h"

class SeqWindow;

class SeqWindowElement
{
public:
  SeqWindowElement();
  ~SeqWindowElement();

  void init(window_size_t w, seq_nr_t m);

  seq_nr_t max_;
  window_size_t pos_;
  uint8_t* window_;
};

class SeqWindow
{
public:
  typedef std::map<sender_id_t, SeqWindowElement> SenderMap;

  SeqWindow(window_size_t w);
  ~SeqWindow();

  bool checkAndAdd(sender_id_t sender, seq_nr_t seq_nr);
  void clear(sender_id_t sender);
  void clear();

private:
  window_size_t window_size_;
  Mutex mutex_;
  SenderMap sender_;

  SeqWindow(const SeqWindow& s);
  void operator=(const SeqWindow& s);

  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    Lock lock(mutex_);
    //unsigned int serial = (unsigned int) window_size_;
    //window_size_t serial = (window_size_t) window_size_;
    ar& window_size_;
    //TODO: Do not sync complete Sender Map!
    // ar & sender_;
  }


};

#endif
