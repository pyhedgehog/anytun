/*
 * anytun
 *
 * The secure anycast tunneling protocol (satp) defines a protocol used
 * for communication between any combination of unicast and anycast
 * tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 * mode and allows tunneling of every ETHER TYPE protocol (e.g.
 * ethernet, ip, arp ...). satp directly includes cryptography and
 * message authentication based on the methodes used by SRTP.  It is
 * intended to deliver a generic, scaleable and secure solution for
 * tunneling and relaying of packets of any protocol.
 *
 *
 * Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _RTPSESSION_H_
#define _RTPSESSION_H_

#include "threadUtils.hpp"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

class RtpSession
{
public:
	RtpSession();

  void init();

  bool isDead();
  bool isDead(bool d);

  std::string getLocalAddr();
  RtpSession& setLocalAddr(std::string a);
  u_int16_t getLocalPort1();
  RtpSession& setLocalPort1(u_int16_t p);
  u_int16_t getLocalPort2();
  RtpSession& setLocalPort2(u_int16_t p);


  u_int16_t getRemotePort1();
  RtpSession& setRemotePort1(u_int16_t p);
  std::string getRemoteAddr1();
  RtpSession& setRemoteAddr1(std::string a);

  u_int16_t getRemotePort2();
  RtpSession& setRemotePort2(u_int16_t p);
  std::string getRemoteAddr2();
  RtpSession& setRemoteAddr2(std::string a);

private:
	RtpSession(const RtpSession & src);
  
  void reinit();

  //TODO: check if this is ok
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
	{    
    Lock lock(mutex_);

    std::string old_local_addr = local_addr_;
    u_int16_t old_local_port1 = local_port1_;
    u_int16_t old_local_port2 = local_port2_;

    ar & dead_;
    ar & local_addr_;
    ar & local_port1_;
    ar & local_port2_;
    ar & remote_addr1_;
    ar & remote_port1_;
    ar & remote_addr2_;
    ar & remote_port2_;

    if(old_local_port1 != local_port1_ || old_local_port2 != local_port2_ || old_local_addr != local_addr_)
      reinit();

    in_sync_ = true;
	}

  bool in_sync_;
	::Mutex mutex_;

  bool dead_;
  std::string local_addr_;
  u_int16_t local_port1_, local_port2_;
  std::string remote_addr1_, remote_addr2_;
  u_int16_t remote_port1_, remote_port2_;
};


#endif
