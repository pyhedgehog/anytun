/**
 *  \file 
 *  \brief Implementation of SyncTcpConnection.
 */
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

#include "syncTcpConnection.h"
#include <boost/bind.hpp>
#include <boost/asio.hpp>

#include <string>

SyncTcpConnection::proto::socket& SyncTcpConnection::socket()
{
  return socket_;
}

void SyncTcpConnection::start()
{
  onConnect(this);
}

void SyncTcpConnection::Send(std::string message)
{
    boost::asio::async_write(socket_, boost::asio::buffer(message),
        boost::bind(&SyncTcpConnection::handle_write, shared_from_this(),
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
}
SyncTcpConnection::SyncTcpConnection(boost::asio::io_service& io_service)
  : socket_(io_service)
{
}

void SyncTcpConnection::handle_write(const boost::system::error_code& /*error*/,
  size_t /*bytes_transferred*/)
{
}
