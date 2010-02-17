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

#ifndef ANYTUN_resolver_h_INCLUDED
#define ANYTUN_resolver_h_INCLUDED

#include <queue>
#include <boost/asio.hpp>
#include <boost/function.hpp>

#include "datatypes.h"
#include "threadUtils.hpp"

typedef boost::function<void (boost::asio::ip::udp::resolver::iterator)> UdpResolveCallback;
typedef boost::function<void (boost::asio::ip::tcp::resolver::iterator)> TcpResolveCallback;
typedef boost::function<void (std::runtime_error const&)> ErrorCallback;

template<class Proto>
class ResolveHandler
{
public:
  ResolveHandler(const std::string& addr, const std::string& port, boost::function<void (boost::asio::ip::basic_resolver_iterator<Proto>)> const& onResolve, ErrorCallback const& onError, ResolvAddrType r = ANY);
  void operator()(const boost::system::error_code& e, boost::asio::ip::basic_resolver_iterator<Proto>);

private:
  std::string addr_;
  std::string port_;
  boost::function<void (const boost::asio::ip::basic_resolver_iterator<Proto>)> onResolve_;
  ErrorCallback onError_;
  ResolvAddrType resolv_addr_type_;
};

typedef ResolveHandler<boost::asio::ip::udp> UdpResolveHandler;
typedef ResolveHandler<boost::asio::ip::tcp> TcpResolveHandler;

class Resolver
{
public:
  static Resolver& instance();

  void init();
  void run();

  void resolveUdp(const std::string& addr, const std::string& port, UdpResolveCallback const& onResolve, ErrorCallback const& onError, ResolvAddrType r = ANY);
  void resolveTcp(const std::string& addr, const std::string& port, TcpResolveCallback const& onResolve, ErrorCallback const& onError, ResolvAddrType r = ANY);

private:
  Resolver();
  ~Resolver();
  Resolver(const Resolver& r);
  void operator=(const Resolver& r);

  static Resolver* inst;
  static ::Mutex instMutex;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(Resolver::inst != 0) {
        delete Resolver::inst;
      }
    }
  };
  friend class instanceCleaner;

  boost::asio::io_service io_service_;
  boost::asio::ip::udp::resolver udp_resolver_;
  boost::asio::ip::tcp::resolver tcp_resolver_;
  boost::thread* thread_;
};

extern Resolver& gResolver;

#endif
