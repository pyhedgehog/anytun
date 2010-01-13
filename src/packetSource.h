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

#ifndef ANYTUN_packetSource_h_INCLUDED
#define ANYTUN_packetSource_h_INCLUDED

#include <boost/asio.hpp>
#include <list>
#include <queue>

#include "datatypes.h"
#include "threadUtils.hpp"

// TODO: fix this when other packetSource types are introduced
typedef boost::asio::ip::udp::endpoint PacketSourceEndpoint;
typedef boost::asio::ip::udp::resolver::iterator PacketSourceResolverIt;

class PacketSource
{
public:
  virtual ~PacketSource() {}

  virtual u_int32_t recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote) = 0;
  virtual void send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote) = 0;

  void waitUntilReady();

protected:
  Semaphore ready_sem_;
};

class UDPPacketSource : public PacketSource
{  
public:
  typedef boost::asio::ip::udp proto;

  UDPPacketSource(std::string localaddr, std::string port);
  ~UDPPacketSource();

  u_int32_t recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote);
  void send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote);

  void onResolve(PacketSourceResolverIt& it);
  void onError(const std::runtime_error& e);

private:
  boost::asio::io_service io_service_;
  
  typedef struct {
    u_int8_t* buf_;
    u_int32_t len_;
    proto::socket* sock_;
  } sockets_element_t;
  std::list<sockets_element_t> sockets_;

  typedef struct {
    u_int8_t* buf_;
    u_int32_t len_;
    proto::socket* sock_;
    PacketSourceEndpoint remote_;
  } thread_result_t;
  std::queue<thread_result_t> thread_result_queue_;
  Mutex thread_result_mutex_;
  Semaphore thread_result_sem_;
  sockets_element_t last_recv_sock_;

  void recv_thread(thread_result_t result);
};

#endif
