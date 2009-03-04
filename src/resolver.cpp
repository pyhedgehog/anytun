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

template<class Proto> ResolveHandler<Proto>::ResolveHandler(const std::string& addr, const std::string& port, boost::function<void(boost::asio::ip::basic_endpoint<Proto>)> const& onResolve) : addr_(addr), port_(port), callback_(onResolve)
{
}

template<class Proto> void ResolveHandler<Proto>::operator()(const boost::system::error_code& e, const boost::asio::ip::basic_resolver_iterator<Proto> endpointIt)
{
  cLog.msg(Log::PRIO_DEBUG) << "ResolveHandler<" << typeid(Proto).name() << ">() called, addr='" << addr_ << "', port='" << port_ << "'";
  if(boost::system::posix_error::success == e) {
	  callback_(*endpointIt);
  } else {
	  cLog.msg(Log::PRIO_ERROR) << "ResolveHandler<" << typeid(Proto).name() << ">(): " << e;
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

void Resolver::run(/*void* s*/)
{
  //Resolver* self = reinterpret_cast<Resolver*>(s);

  cLog.msg(Log::PRIO_DEBUG) << "Resolver Thread started";

  while(1) {
    /*self->*/io_service_.run();
    /*self->*/io_service_.reset();
    boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  }
}

void Resolver::resolveUdp(const std::string& addr, const std::string& port, boost::function<void (boost::asio::ip::udp::endpoint)> const& onResolve)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv UDP: " << addr << " " << port;

  boost::asio::ip::udp::resolver::query query(addr, port);
  UdpResolveHandler handler(addr, port, onResolve);
  udp_resolver_.async_resolve(query, handler);
}

void Resolver::resolveTcp(const std::string& addr, const std::string& port, boost::function<void (boost::asio::ip::tcp::endpoint)> const& onResolve)
{
  cLog.msg(Log::PRIO_DEBUG) << "trying to resolv TCP: " << addr << " " << port;

  boost::asio::ip::tcp::resolver::query query(addr, port);
  TcpResolveHandler handler(addr, port, onResolve);
  tcp_resolver_.async_resolve(query, handler); 
}
