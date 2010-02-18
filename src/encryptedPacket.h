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

#ifndef ANYTUN_encryptedPacket_h_INCLUDED
#define ANYTUN_encryptedPacket_h_INCLUDED

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
  EncryptedPacket(uint32_t payload_length, uint32_t auth_tag_length, bool allow_realloc = false);

  /**
   * Packet destructor
   */
  ~EncryptedPacket() {};

  /**
   * Get the length of the header
   * @return the length of the header
   */
  static uint32_t getHeaderLength();

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
  uint32_t getPayloadLength() const;

  /**
   * Set the length of the payload
   * @param length length of the payload
   */
  void setPayloadLength(uint32_t payload_length);

  /**
   * Get the the payload
   * @return the Pointer to the payload
   */
  uint8_t* getPayload();


  uint8_t* getAuthenticatedPortion();
  uint32_t getAuthenticatedPortionLength();

  void withAuthTag(bool b);
  void addAuthTag();
  void removeAuthTag();
  uint8_t* getAuthTag();
  uint32_t getAuthTagLength();

private:
  EncryptedPacket();
  EncryptedPacket(const EncryptedPacket& src);

  void reinit();

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
  struct ATTR_PACKED HeaderStruct {
    seq_nr_t seq_nr;
    sender_id_t sender_id;
    mux_t mux;
  };
#ifdef _MSC_VER
#pragma pack(pop)
#endif

  struct HeaderStruct* header_;
  uint8_t* payload_;
  uint8_t* auth_tag_;
  uint32_t  auth_tag_length_;
};

#endif
