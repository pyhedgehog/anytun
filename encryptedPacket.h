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

#ifndef _ENCRYPTED_PACKET_H_
#define _ENCRYPTED_PACKET_H_

#include "datatypes.h"
#include "buffer.h"
#include "authTag.h"
class Cypher;
class EncryptedPacket : public Buffer
{
public:

  /**
   * Packet constructor
   * @param max_payload_length maximum length of encrypted payload
   */
  EncryptedPacket(u_int32_t max_payload_length);

  /**
   * Packet destructor
   */
  ~EncryptedPacket();

  /**
   * Get the sequence number
   * @return seqence number
   */
  seq_nr_t getSeqNr() const;

  /**
   * Set the seqence number
   * @param seq_nr sequence number
   */
  void setSeqNr(seq_nr_t seq_nr);

  /**
   * Get the sender id
   * @return sender id
   */
  sender_id_t getSenderId() const;

  /**
   * Set the sender id
   * @param sender_id sender id
   */
  void setSenderId(sender_id_t sender_id);

  /**
   * Get the mulitplex id
   * @return multiplex id
   */
  mux_t getMux() const;

  /**
   * Set the multiplex id
   * @param mux multiplex id
   */
  void setMux(mux_t mux);

  /**
   * Set the header of a packet
   * @param seq_nr sequence number
   * @param sender_id sender id
   * @param mux multiplex id
   */
  void setHeader(seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

  /** 
   * Get the maximum payload size
   * @return maximum payload size
   */
  u_int32_t getMaxLength() const;

  /**
   * Set the real length of the payload
   * @param length the real length of the payload, has to be smaller than the maximum payload size!
   */
  void setLength(u_int32_t length);

  bool hasAuthTag() const;
  void withAuthTag(bool b);
  AuthTag getAuthTag() const;
  void setAuthTag(AuthTag& tag);

	void setPayloadLength(u_int32_t payload_length);

                       
//  bool hasHeader() const;
//  Packet& withHeader(bool b);
//  Packet& addHeader(seq_nr_t seq_nr, sender_id_t sender_id);
//  Packet& withAuthTag(bool b);
//  AuthTag getAuthTag() const;
//  Packet& addAuthTag(AuthTag auth_tag);

private:
  EncryptedPacket();
  EncryptedPacket(const EncryptedPacket &src);
  struct HeaderStruct
  {
    seq_nr_t seq_nr;
    sender_id_t sender_id;
    mux_t mux;
  }__attribute__((__packed__));

  struct HeaderStruct* header_;
  AuthTag* auth_tag_;
  u_int32_t max_length_;

  static const u_int32_t AUTHTAG_SIZE = 10;     // 10byte
protected:
	friend class Cypher;
	u_int8_t * payload_;
	u_int32_t payload_length_;
};

#endif
