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

#include <arpa/inet.h>

#include "datatypes.h"

#include "package.h"

Package::Package()
{
  header_ = 0;
  payload_type_ = 0;
  auth_tag_ = 0;                
}

Package::Package(u_int32_t length) : Buffer(length)
{
  header_ = 0;
  payload_type_ = 0;
  auth_tag_ = 0;                
}

Package::Package(const Buffer &src) : Buffer(src)
{
  header_ = 0;
  payload_type_ = 0;
  auth_tag_ = 0;                
}
  
bool Package::hasHeader() const
{
  return header_;
}

Package& Package::withHeader(bool b)
{
  if(b && length_ >= sizeof(struct HeaderStruct))
    header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  else
    header_ = 0;

  return *this;
}

seq_nr_t Package::getSeqNr() const
{
  if(!header_)
    return 0;

  return SEQ_NR_T_NTOH(header_->seq_nr);
}

sender_id_t Package::getSenderId() const
{
  if(!header_)
    return 0;

  return SENDER_ID_T_NTOH(header_->sender_id);
}

Package& Package::addHeader(seq_nr_t seq_nr, sender_id_t sender_id)
{
  if(!header_)
  {
    if(sizeof(struct HeaderStruct) > resizeFront(length_ + sizeof(struct HeaderStruct)))
      return *this;

    header_ = reinterpret_cast<struct HeaderStruct*>(buf_);
  }
  header_->seq_nr = SEQ_NR_T_HTON(seq_nr);
  header_->sender_id = SENDER_ID_T_HTON(sender_id);
  return *this;
}

Package& Package::removeHeader()
{
  if(!header_)
    return *this;

  if(length_ >= sizeof(struct HeaderStruct))
    resizeFront(length_ - sizeof(struct HeaderStruct));

  header_ = 0;
  
  return *this;
}

Package& Package::setSeqNr(seq_nr_t seq_nr)
{
  if(header_)
    header_->seq_nr = SEQ_NR_T_HTON(seq_nr);

  return *this;
}

Package& Package::setSenderId(sender_id_t sender_id)
{
  if(header_)
    header_->sender_id = SENDER_ID_T_HTON(sender_id);

  return *this;
}
