/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <boost/bind.hpp>
#include <boost/system/error_code.hpp>

#include "resolver.h"
#include "log.h"

using ::boost::asio::ip::udp;
using ::boost::asio::ip::tcp;

template<class Proto>
void waitAndEnqueue(uint32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_resolver_iterator<Proto>)> const& onResolve, ErrorCallback const& onError, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_ERROR) << "the resolver only supports udp and tcp";
}

template<>
void waitAndEnqueue(uint32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_resolver_iterator<udp>)> const& onResolve, ErrorCallback const& onError, ResolvAddrType r)
{
  boost::this_thread::sleep(boost::posix_time::milliseconds(s * 1000));
  gResolver.resolveUdp(addr, port, onResolve, onError, r);
}

template<>
void waitAndEnqueue(uint32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_resolver_iterator<tcp>)> const& onResolve, ErrorCallback const& onError, ResolvAddrType r)
{
  boost::this_thread::sleep(boost::posix_time::milliseconds(s * 1000));
  gResolver.resolveTcp(addr, port, onResolve, onError, r);
}


template<class Proto>
ResolveHandler<Proto>::ResolveHandler(const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_resolver_iterator<Proto>)> const& onResolve, ErrorCallback const& onError, ResolvAddrType r) : addr_(addr), port_(port), onResolve_(onResolve), onError_(onError), resolv_addr_type_(r)
{
}

template<class Proto>
void ResolveHandler<Proto>::operator()(const boost::system::error_code& e, boost::asio::ip::basic_resolver_iterator<Proto> endpointIt)
{
  if(boost::system::posix_error::success == e) {
    try {
      onResolve_(endpointIt);
    } catch(const std::runtime_error& e) {
      onError_(e);
    }
  } else {
    cLog.msg(Log::PRIO_ERROR) << "Error while resolving '" << addr_ << "' '" << port_ << "', retrying in 10 sec.";
    boost::thread(boost::bind(waitAndEnqueue<Proto>, 10, addr_, port_, onResolve_, onError_, resolv_addr_type_));
  }
}

Resolver& gResolver = Resolver::instance();

Resolver& Resolver::instance()
{
  static Resolver instance;
  return instance;
}

Resolver::Resolver() : udp_resolver_(io_service_), tcp_resolver_(io_service_), thread_(NULL)
{
}

Resolver::~Resolver()
{
  if(thread_) {
    delete thread_;
  }
}

void Resolver::init()
{
  if(!thread_) {
    thread_ = new boost::thread(boost::bind(&Resolver::run, this));
  }
}

void Resolver::run()
{
  cLog.msg(Log::PRIO_DEBUG) << "Resolver Thread started";

  for(;;) {
    try {
      io_service_.run();
      io_service_.reset();
      boost::this_thread::sleep(boost::posix_time::milliseconds(250));
    } catch(const std::runtime_error& e) {
      cLog.msg(Log::PRIO_ERROR) << "resolver caught runtime error, restarting: " << e.what();
    } catch(const std::exception& e) {
      cLog.msg(Log::PRIO_ERROR) << "resolver caught exception, restarting: " << e.what();
    }
  }
}


void Resolver::resolveUdp(const std::string& addr, const std::string& port, UdpResolveCallback const& onResolve, ErrorCallback const& onError, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv UDP: '" << addr << "' '" << port << "'";

  boost::shared_ptr<udp::resolver::query> query;
  if(addr != "") {
    switch(r) {
    case IPV4_ONLY:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(udp::v4(), addr, port));
      break;
    case IPV6_ONLY:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(udp::v6(), addr, port));
      break;
    default:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(addr, port));
      break;
    }
  } else {
    switch(r) {
    case IPV4_ONLY:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(udp::v4(), port));
      break;
    case IPV6_ONLY:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(udp::v6(), port));
      break;
    default:
      query = boost::shared_ptr<udp::resolver::query>(new udp::resolver::query(port));
      break;
    }
  }
  UdpResolveHandler handler(addr, port, onResolve, onError, r);
  udp_resolver_.async_resolve(*query, handler);
}

void Resolver::resolveTcp(const std::string& addr, const std::string& port, TcpResolveCallback const& onResolve, ErrorCallback const& onError, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv TCP: '" << addr << "' '" << port << "'";

  boost::shared_ptr<tcp::resolver::query> query;
  if(addr != "") {
    switch(r) {
    case IPV4_ONLY:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v4(), addr, port));
      break;
    case IPV6_ONLY:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v6(), addr, port));
      break;
    default:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(addr, port));
      break;
    }
  } else {
    switch(r) {
    case IPV4_ONLY:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v4(), port));
      break;
    case IPV6_ONLY:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v6(), port));
      break;
    default:
      query = boost::shared_ptr<tcp::resolver::query>(new tcp::resolver::query(port));
      break;
    }
  }
  TcpResolveHandler handler(addr, port, onResolve, onError, r);
  tcp_resolver_.async_resolve(*query, handler);
}
