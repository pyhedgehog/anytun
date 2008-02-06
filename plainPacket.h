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

#ifndef _PLAIN_PACKET_H_
#define _PLAIN_PACKET_H_

#include "datatypes.h"
#include "buffer.h"

class Cypher;
/**
 * plain SATP packet class<br>
 * includes payload_type and payload
 */

class PlainPacket : public Buffer
{
public:
  ~PlainPacket();

  /**
   * Packet constructor
   * @param max_payload_length maximum payload length
   */
  PlainPacket(u_int32_t max_payload_length);

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

	void setCompletePayloadLength(u_int32_t payload_length);
	u_int32_t getCompletePayloadLength();

  /**
   * Set the real payload length
   * @param length the real payload length
   */
  //void setRealPayloadLengt(u_int32_t length);

  /**
   * Get the real payload length
   * @return the real length of the payload
   */
  //u_int32_t getRealPayloadLength();

  /**
   * Set the length of the payload
   * @param length length of the payload
   */
  void setLength(u_int32_t length);

  /**
   * Get the size of the allocated memory for the payload
   * @return maximum size of payload
   */
  u_int32_t getMaxLength() const; 

private:
  PlainPacket();
  PlainPacket(const PlainPacket &src);
	void splitPayload();
  u_int32_t max_length_;
  payload_type_t* payload_type_;
protected:
	friend class Cypher;
	u_int8_t * complete_payload_;
	u_int32_t complete_payload_length_;
};

#endif
