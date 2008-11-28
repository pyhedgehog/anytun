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

#ifndef _ENCRYPTED_PACKET_H_
#define _ENCRYPTED_PACKET_H_

#include "datatypes.h"
#include "buffer.h"

class Cipher;
class EncryptedPacket : public Buffer
{
public:

  /**
   * Packet constructor
   * @param the length of the payload 
   * @param allow reallocation of buffer
   */
  EncryptedPacket(u_int32_t payload_length, bool allow_realloc = false);

  /**
   * Packet destructor
   */
  ~EncryptedPacket() {};

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
   * Get the length of the payload
   * @return the length of the payload
   */
	u_int32_t getPayloadLength() const;

  /**
   * Set the length of the payload
   * @param length length of the payload
   */
  void setPayloadLength(u_int32_t payload_length);

  /**
   * Get the the payload
   * @return the Pointer to the payload
   */
  u_int8_t* getPayload();


  u_int8_t* getAuthenticatedPortion();
  u_int32_t getAuthenticatedPortionLength();

  void withAuthTag(bool b);
  void addAuthTag();
  void removeAuthTag();
  u_int8_t* getAuthTag();
  u_int32_t getAuthTagLength();
                      
private:
  EncryptedPacket();
  EncryptedPacket(const EncryptedPacket &src);

  void reinit();

  struct HeaderStruct
  {
    seq_nr_t seq_nr;
    sender_id_t sender_id;
    mux_t mux;
  }
#ifndef NOPACKED
  __attribute__((__packed__))
#endif	  
;

  struct HeaderStruct* header_;
	u_int8_t * payload_;
  u_int8_t * auth_tag_;
  static const u_int32_t AUTHTAG_SIZE = 10;  // TODO: hardcoded size
};

#endif
