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

#ifndef _SEQ_WINDOW_H_
#define _SEQ_WINDOW_H_

#include <map>
#include <deque>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include "threadUtils.hpp"
#include "datatypes.h"

class SeqWindow
{
public:
  typedef std::deque<seq_nr_t> SeqDeque;
  typedef std::map<sender_id_t, SeqDeque> SenderMap;

  SeqWindow(window_size_t w);
  ~SeqWindow();

  SeqDeque::size_type getLength(sender_id_t sender);
  bool hasSeqNr(sender_id_t sender, seq_nr_t seq);
  void addSeqNr(sender_id_t sender, seq_nr_t seq);
  void clear(sender_id_t sender);
  void clear();


private:
  SeqWindow(const SeqWindow &s);
  void operator=(const SeqWindow &s);

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		//unsigned int serial = (unsigned int) window_size_;
		//window_size_t serial = (window_size_t) window_size_;
  	ar & window_size_;
  	//TODO: Do not sync complete Sender Map!
  	// ar & sender_;
  }
 

  window_size_t window_size_;
  Mutex mutex_;
  SenderMap sender_;
};

#endif
