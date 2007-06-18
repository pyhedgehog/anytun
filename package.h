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

#ifndef _PACKAGE_H_
#define _PACKAGE_H_

#include "datatypes.h"
#include "buffer.h"

class Package : public Buffer
{
public:
  Package();
  Package(u_int32_t length);
  Package(const Buffer &src);
  
  bool hasHeader() const;
  Package& withHeader(bool b);
  seq_nr_t getSeqNr() const;
  sender_id_t getSenderId() const;
  Package& addHeader(seq_nr_t seq_nr, sender_id_t sender_id);
  Package& removeHeader();
  Package& setSeqNr(seq_nr_t seq_nr);
  Package& setSenderId(sender_id_t sender_id);
                       
  
  bool hasPayloadType() const;
  Package& withPayloadType(bool b);
  payload_type_t getPayloadType() const;  
  Package& addPayloadType(payload_type_t payload_type);
  Package& removePayloadType();
  
  bool hasAuthTag() const;
  Package& withAuthTag(bool b);
  auth_tag_t getAuthTag() const;
  Package& addAuthTag(auth_tag_t auth_tag);
  Package& removeAuthTag();                     

private:
  struct HeaderStruct
  {
    seq_nr_t seq_nr;
    sender_id_t sender_id;
  }__attribute__((__packed__));
  struct HeaderStruct* header_;
  payload_type_t* payload_type_;
  auth_tag_t* auth_tag_;
};

#endif
