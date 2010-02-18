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

#ifndef ANYTUN_plainPacket_h_INCLUDED
#define ANYTUN_plainPacket_h_INCLUDED

#include "datatypes.h"
#include "buffer.h"

#include "networkAddress.h"

class Cipher;
/**
 * plain SATP packet class<br>
 * includes payload_type and payload
 */

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0000
#define PAYLOAD_TYPE_TUN4 0x0800
#define PAYLOAD_TYPE_TUN6 0x86DD

class PlainPacket : public Buffer
{
public:
  /**
   * Packet constructor
   * @param the length of the payload
   * @param allow reallocation of buffer
   */
  PlainPacket(uint32_t payload_length, bool allow_realloc = false);

  /**
   * Packet destructor
   */
  ~PlainPacket() {};

  /**
   * Get the length of the header
   * @return the length of the header
   */
  static uint32_t getHeaderLength();

  /**
   * Get the payload type
   * @return the id of the payload type
   */
  payload_type_t getPayloadType() const;

  /**
   * Set the payload type
   * @param payload_type payload type id
   */
  void setPayloadType(payload_type_t payload_type);

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

  //  NetworkAddress getSrcAddr() const;
  NetworkAddress getDstAddr() const;

private:
  PlainPacket();
  PlainPacket(const PlainPacket& src);

  void reinit();

  payload_type_t* payload_type_;
  uint8_t* payload_;
};

#endif
