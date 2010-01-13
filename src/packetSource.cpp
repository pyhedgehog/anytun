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
  gResolver.resolveUdp(localaddr, port, boost::bind(&UDPPacketSource::onResolve, this, _1), boost::bind(&UDPPacketSource::onError, this, _1), gOpt.getResolvAddrType());
}

UDPPacketSource::~UDPPacketSource()
{
  std::list<sockets_element_t>::iterator it = sockets_.begin();
  for(;it != sockets_.end(); ++it) {
/// this might be a needed by the receiver thread, TODO cleanup
//    delete[](it->buf_);
//    delete(it->sem_);
//    delete(it->sock_);
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
    sock.sem_ = NULL;
    sock.sock_ = new proto::socket(io_service_);
    if(!sock.sock_)
      AnytunError::throwErr() << "memory error";

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

      // prepare multi-socket recv
  if(sockets_.size() > 1) {
    std::list<sockets_element_t>::iterator it = sockets_.begin();
    for(;it != sockets_.end(); ++it) {
      it->len_ = 1600; // TODO packet size
      it->buf_ = new u_int8_t[it->len_];
      if(!it->buf_)
        AnytunError::throwErr() << "memory error";
      
      it->sem_ = new Semaphore();
      if(!it->sem_) {
        delete[](it->buf_);
        AnytunError::throwErr() << "memory error";
      }

      boost::thread(boost::bind(&UDPPacketSource::recv_thread, this, it));
      it->sem_->up();
    }

  }

  ready_sem_.up();
}

void UDPPacketSource::onError(const std::runtime_error& e)
{
  gSignalController.inject(SIGERROR, e.what());
}

void UDPPacketSource::recv_thread(std::list<sockets_element_t>::iterator it)
{
  cLog.msg(Log::PRIO_DEBUG) << "started receiver thread for " << it->sock_->local_endpoint();

  thread_result_t result;
  result.it_ = it;
  for(;;) {
    it->sem_->down();

    cLog.msg(Log::PRIO_DEBUG) << "calling recv() for " << it->sock_->local_endpoint();

    result.len_ = static_cast<u_int32_t>(it->sock_->receive_from(boost::asio::buffer(it->buf_, it->len_), result.remote_));
    {
      Lock lock(thread_result_mutex_);
      thread_result_queue_.push(result);
    }
    thread_result_sem_.up();
  }
}

u_int32_t UDPPacketSource::recv(u_int8_t* buf, u_int32_t len, PacketSourceEndpoint& remote)
{
  if(sockets_.size() == 1)
    return static_cast<u_int32_t>(sockets_.front().sock_->receive_from(boost::asio::buffer(buf, len), remote));

  thread_result_sem_.down();
  thread_result_t result;
  {
    Lock lock(thread_result_mutex_);
    result = thread_result_queue_.front();
    thread_result_queue_.pop();
  }
  remote = result.remote_;
  std::memcpy(buf, result.it_->buf_, (len < result.len_) ? len : result.len_);
  len = (len < result.len_) ? len : result.len_;
  result.it_->sem_->up();

  return len;
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

