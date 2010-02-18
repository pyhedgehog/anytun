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
#include <boost/thread.hpp>
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

  virtual uint32_t recv(uint8_t* buf, uint32_t len, PacketSourceEndpoint& remote) = 0;
  virtual void send(uint8_t* buf, uint32_t len, PacketSourceEndpoint remote) = 0;

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

  uint32_t recv(uint8_t* buf, uint32_t len, PacketSourceEndpoint& remote);
  void send(uint8_t* buf, uint32_t len, PacketSourceEndpoint remote);

  void onResolve(PacketSourceResolverIt& it);
  void onError(const std::runtime_error& e);

private:
  boost::asio::io_service io_service_;

  typedef struct {
    uint8_t* buf_;
    uint32_t len_;
    proto::socket* sock_;
    Semaphore* sem_;
  } SocketsElement;
  std::list<SocketsElement> sockets_;

  void recv_thread(std::list<SocketsElement>::iterator it);
  typedef struct {
    uint32_t len_;
    PacketSourceEndpoint remote_;
    std::list<SocketsElement>::iterator it_;
  } ThreadResult;
  std::queue<ThreadResult> thread_result_queue_;
  Mutex thread_result_mutex_;
  Semaphore thread_result_sem_;
};

#endif
