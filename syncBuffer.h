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

#ifndef _SYNCBUFFER_H_
#define _SYNCBUFFER_H_

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include "buffer.h"
#include <iostream>
#include "datatypes.h"

class SyncBuffer : public Buffer
{
public:
		SyncBuffer() : Buffer(){  std::cout << " SyncBuffer() -> Length: " << length_ << std::endl;};
		SyncBuffer(u_int32_t length) : Buffer(length){ std::cout << "SyncBuffer(u_int32_t length) Length: " << length_ << std::endl; };
		SyncBuffer(Buffer b): Buffer(b) {std::cout << " SyncBuffer(Buffer b) " << length_ <<  std::endl;};
		SyncBuffer(u_int8_t* data, u_int32_t length): Buffer(data,length) { std::cout << "SyncBuffer(u_int8_t* data, u_int32_t length)-> Length: "<< length_ << std::endl;};
		SyncBuffer(const SyncBuffer & src) : Buffer(src) {std::cout << " SyncBuffer(const SyncBuffer & src)-> Length: "<< length_ << std::endl;};
private:
	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		std::cout << "Length: " << length_ << std::endl;
    ar & length_;
		//for(u_int32_t i = 0; i < length_; i++)
		//		ar & (*this)[i];
	}
};

#endif
