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

#include "syncServer.h"

//using asio::ip::tcp;

SyncServer::SyncServer(boost::asio::io_service& io_service, SyncTcpConnection::proto::endpoint tcp_endpoint )
    : acceptor_(io_service, tcp_endpoint)
{
  start_accept();
}

void SyncServer::start_accept()
{
  Lock lock(mutex_);
  SyncTcpConnection::pointer new_connection =
    SyncTcpConnection::create(acceptor_.io_service());
  conns_.push_back(new_connection);
  
  acceptor_.async_accept(new_connection->socket(),
                         boost::bind(&SyncServer::handle_accept, this, new_connection,
                                     boost::asio::placeholders::error));
}

void SyncServer::send(std::string message)
{
  Lock lock(mutex_);
  for(std::list<SyncTcpConnection::pointer>::iterator it = conns_.begin() ;it != conns_.end(); ++it) {
    (*it)->Send(message);
  }
}

void  SyncServer::handle_accept(SyncTcpConnection::pointer new_connection,
    const boost::system::error_code& error)
{
  if (!error)
  {
    new_connection->onConnect=onConnect;
    new_connection->start();
    start_accept();
  }
}
