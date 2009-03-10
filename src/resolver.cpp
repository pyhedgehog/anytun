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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/bind.hpp>
#include <boost/system/error_code.hpp>

#include "resolver.h"
#include "log.h"
#include "signalController.h"

using ::boost::asio::ip::udp;
using ::boost::asio::ip::tcp;

template<class Proto>
void waitAndEnqueue(u_int32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_endpoint<Proto>)> const& onResolve, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_ERROR) << "the resolver only supports udp and tcp";
}

template<>
void waitAndEnqueue(u_int32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_endpoint<udp>)> const& onResolve, ResolvAddrType r)
{
  boost::this_thread::sleep(boost::posix_time::milliseconds(s * 1000));
  gResolver.resolveUdp(addr, port, onResolve, r);
}

template<>
void waitAndEnqueue(u_int32_t s, const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_endpoint<tcp>)> const& onResolve, ResolvAddrType r)
{
  boost::this_thread::sleep(boost::posix_time::milliseconds(s * 1000));
  gResolver.resolveTcp(addr, port, onResolve, r);
}


template<class Proto>
ResolveHandler<Proto>::ResolveHandler(const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_endpoint<Proto>)> const& onResolve, ResolvAddrType r) : addr_(addr), port_(port), callback_(onResolve), resolv_addr_type_(r)
{
}

template<class Proto>
void ResolveHandler<Proto>::operator()(const boost::system::error_code& e, const boost::asio::ip::basic_resolver_iterator<Proto> endpointIt)
{
  if(boost::system::posix_error::success == e) {
    try {
      callback_(*endpointIt);
    }
    catch(const std::runtime_error& e)
    {
      gSignalController.inject(SIGERROR, e.what());
    }
  } else {
	  cLog.msg(Log::PRIO_ERROR) << "Error while resolving '" << addr_ << "' '" << port_ << "', retrying in 10 sec.";
    boost::thread(boost::bind(waitAndEnqueue<Proto>, 10, addr_, port_, callback_, resolv_addr_type_));
  }
}

Resolver* Resolver::inst = NULL;
Mutex Resolver::instMutex;
Resolver& gResolver = Resolver::instance();

Resolver& Resolver::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new Resolver();
  
  return *inst;
}

Resolver::Resolver() : udp_resolver_(io_service_), tcp_resolver_(io_service_), thread_(NULL)
{
}

Resolver::~Resolver()
{
  if(thread_)
    delete thread_;
}

void Resolver::init()
{
  if(!thread_)
	  thread_ = new boost::thread(boost::bind(&Resolver::run, this));
}

void Resolver::run()
{
  cLog.msg(Log::PRIO_DEBUG) << "Resolver Thread started";

  while(1) {
    try {
      io_service_.run();
      io_service_.reset();
      boost::this_thread::sleep(boost::posix_time::milliseconds(250));
    }
    catch(const std::runtime_error& e)
    {
      cLog.msg(Log::PRIO_ERROR) << "resolver caught runtime error, restarting: " << e.what();
    }
    catch(const std::exception& e)
    {
      cLog.msg(Log::PRIO_ERROR) << "resolver caught exception, restarting: " << e.what();
    }
  }
}


void Resolver::resolveUdp(const std::string& addr, const std::string& port, boost::function<void (udp::endpoint)> const& onResolve, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv UDP: '" << addr << "' '" << port << "'";

  std::auto_ptr<udp::resolver::query> query;
  if(addr != "") {
    switch(r) {
    case IPV4_ONLY: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(udp::v4(), addr, port)); break;
    case IPV6_ONLY: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(udp::v6(), addr, port)); break;
    default: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(addr, port)); break;
    }
  }
  else {
    switch(r) {
    case IPV4_ONLY: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(udp::v4(), port)); break;
    case IPV6_ONLY: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(udp::v6(), port)); break;
    default: query = std::auto_ptr<udp::resolver::query>(new udp::resolver::query(port)); break;
    }
  }
  UdpResolveHandler handler(addr, port, onResolve, r);
  udp_resolver_.async_resolve(*query, handler);
}

void Resolver::resolveTcp(const std::string& addr, const std::string& port, boost::function<void (tcp::endpoint)> const& onResolve, ResolvAddrType r)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv TCP: '" << addr << "' '" << port << "'";

  std::auto_ptr<tcp::resolver::query> query;
  if(addr != "") {
    switch(r) {
    case IPV4_ONLY: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v4(), addr, port)); break;
    case IPV6_ONLY: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v6(), addr, port)); break;
    default: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(addr, port)); break;
    }
  }
  else {
    switch(r) {
    case IPV4_ONLY: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v4(), port)); break;
    case IPV6_ONLY: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(tcp::v6(), port)); break;
    default: query = std::auto_ptr<tcp::resolver::query>(new tcp::resolver::query(port)); break;
    }
  }
  TcpResolveHandler handler(addr, port, onResolve, r);
  tcp_resolver_.async_resolve(*query, handler); 
}