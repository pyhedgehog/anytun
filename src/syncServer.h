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

#ifndef _SYNC_SERVER_H_
#define _SYNC_SERVER_H_
//#include <iostream>
//#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include "threadUtils.hpp"


#include <boost/asio.hpp>
#include <list>
#include "syncTcpConnection.h"

class SyncServer
{
public:
  SyncServer(boost::asio::io_service& io_service, SyncTcpConnection::proto::endpoint tcp_endpoint );
	boost::function<void(SyncTcpConnection *)> onConnect;
  std::list<SyncTcpConnection::pointer> conns_;
	void send(std::string message);
private:
  void start_accept();
  void handle_accept(SyncTcpConnection::pointer new_connection,
      const boost::system::error_code& error);
	Mutex mutex_; //Mutex for list conns_
  SyncTcpConnection::proto::acceptor acceptor_;
};
#endif
