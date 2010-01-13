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

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>

#include "datatypes.h"
#include "packetSource.h"
#include "log.h"
#include "resolver.h"
#include "options.h"
#include "signalController.h"
#include "anytunError.h"

void PacketSource::waitUntilReady()
{
  ready_sem_.down();
}

UDPPacketSource::UDPPacketSource(std::string localaddr, std::string port)
{
  last_recv_sock_.buf_ = NULL;
  last_recv_sock_.len_ = 0;
  last_recv_sock_.sock_ = NULL;
  gResolver.resolveUdp(localaddr, port, boost::bind(&UDPPacketSource::onResolve, this, _1), boost::bind(&UDPPacketSource::onError, this, _1), gOpt.getResolvAddrType());
}

UDPPacketSource::~UDPPacketSource()
{
  std::list<sockets_element_t>::iterator it = sockets_.begin();
  for(;it != sockets_.end(); ++it) {
    delete[](it->buf_);
    delete(it->sock_);
  }
}

void UDPPacketSource::onResolve(PacketSourceResolverIt& it)
{
  while(it != PacketSourceResolverIt()) {
    PacketSourceEndpoint e = *it;
    cLog.msg(Log::PRIO_NOTICE) << "opening socket: " << e;

    sockets_element_t sock;
    sock.buf_ = NULL;
    sock.len_ = 0;
    sock.sock_ = new proto::socket(io_service_);
    sock.sock_->open(e.protocol());
#ifndef _MSC_VER
    if(e.protocol() == proto::v6()) {
      boost::asio::ip::v6_only option(true);
      sock.sock_->set_option(option);
    }
#endif
    sock.sock_->bind(e);
    sockets_.push_back(sock);

    it++;
  }

  ready_sem_.up();
}

void UDPPacketSource::onError(const std::runtime_error& e)
{
  gSignalController.inject(SIGERROR, e.what());
}

void UDPPacketSource::recv_thread(thread_result_t result)
{
  cLog.msg(Log::PRIO_DEBUG) << "started receiver thread for " << result.sock_->local_endpoint();

  result.len_ = static_cast<u_int32_t>(result.sock_->receive_from(boost::asio::buffer(result.buf_, result.len_), result.remote_));
  {
    Lock lock(thread_result_mutex_);
    thread_result_queue_.push(result);
  }
  thread_result_sem_.up();
}

u_int32_t UDPPacketSource::recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote)
{
  if(sockets_.size() == 1)
    return static_cast<u_int32_t>(sockets_.begin()->sock_->receive_from(boost::asio::buffer(buf, len), remote));

  if(!last_recv_sock_.sock_) {
    std::list<sockets_element_t>::iterator it = sockets_.begin();
    for(;it != sockets_.end(); ++it) {
      if(it == sockets_.begin()) {
        it->buf_ = buf; 
        it->len_ = len;
      }
      else {
        it->buf_ = new u_int8_t[len];
        if(!it->buf_)
          AnytunError::throwErr() << "memory error";
        it->len_ = len;
      }

      thread_result_t result;
      result.buf_ = it->buf_;
      result.len_ = it->len_;
      result.sock_ = it->sock_;
      boost::thread(boost::bind(&UDPPacketSource::recv_thread, this, result));
    }
  }
  else {
    thread_result_t result;
    result.buf_ = last_recv_sock_.buf_;
    result.len_ = last_recv_sock_.len_;
    result.sock_ = last_recv_sock_.sock_;
    boost::thread(boost::bind(&UDPPacketSource::recv_thread, this, result));
  }

  thread_result_sem_.down();
  thread_result_t result;
  {
    Lock lock(thread_result_mutex_);
    result = thread_result_queue_.front();
    thread_result_queue_.pop();
  }

  last_recv_sock_.sock_ = result.sock_;
  last_recv_sock_.buf_ = result.buf_;
  last_recv_sock_.len_ = result.len_;
  remote = result.remote_;

  if(result.sock_ != sockets_.begin()->sock_) {
    std::memcpy(buf, result.buf_, (len < result.len_) ? len : result.len_);
    return (len < result.len_) ? len : result.len_;
  }

  return result.len_;
}

void UDPPacketSource::send(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint remote)
{
  std::list<sockets_element_t>::iterator it = sockets_.begin();
  for(;it != sockets_.end(); ++it) {
    if(it->sock_->local_endpoint().protocol() == remote.protocol()) {
      it->sock_->send_to(boost::asio::buffer(buf, len), remote);
      return;
    }
  }
  cLog.msg(Log::PRIO_WARNING) << "no suitable socket found for remote endpoint protocol: " << remote;
}

