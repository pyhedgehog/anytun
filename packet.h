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

#ifndef _PACKET_H_
#define _PACKET_H_

#include "datatypes.h"
#include "buffer.h"

class Packet : public Buffer
{
public:
  Packet();
  Packet(u_int32_t length);
  Packet(const Buffer &src);
  
  bool hasHeader() const;
  Packet& withHeader(bool b);
  seq_nr_t getSeqNr() const;
  sender_id_t getSenderId() const;
  Packet& addHeader(seq_nr_t seq_nr, sender_id_t sender_id);
  Packet& removeHeader();
  Packet& setSeqNr(seq_nr_t seq_nr);
  Packet& setSenderId(sender_id_t sender_id);
                       
  bool hasPayloadType() const;
  Packet& withPayloadType(bool b);
  payload_type_t getPayloadType() const;  
  Packet& addPayloadType(payload_type_t payload_type);
  Packet& removePayloadType();
  
  bool hasAuthTag() const;
  Packet& withAuthTag(bool b);
  auth_tag_t getAuthTag() const;
  Packet& addAuthTag(auth_tag_t auth_tag);
  Packet& removeAuthTag();                     

private:
  struct HeaderStruct
  {
    seq_nr_t seq_nr;
    sender_id_t sender_id;
  }__attribute__((__packed__));
  bool has_header_;
  bool has_payload_type_;
  bool has_auth_tag_;
};

#endif
