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

#ifndef ANYTUN_syncServer_h_INCLUDED
#define ANYTUN_syncServer_h_INCLUDED

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include "threadUtils.hpp"


#include <boost/asio.hpp>
#include <list>
#include "syncTcpConnection.h"

typedef boost::function<void (SyncTcpConnection*)> ConnectCallback;

class SyncServer
{
public:
  SyncServer(std::string localaddr, std::string port, ConnectCallback onConnect);
  ~SyncServer();
  void onResolve(SyncTcpConnection::proto::resolver::iterator& it);
  void onResolvError(const std::runtime_error& e);

  void run();
  void send(std::string message);

  std::list<SyncTcpConnection::pointer> conns_;

private:
  Mutex mutex_; //Mutex for list conns_
  boost::asio::io_service io_service_;
  typedef struct {
    SyncTcpConnection::proto::acceptor* acceptor_;
    bool started_;
  } AcceptorsElement;
  std::list<AcceptorsElement> acceptors_;
  ConnectCallback onConnect_;
  Semaphore ready_sem_;

  void start_accept();
  void handle_accept(SyncTcpConnection::pointer new_connection, const boost::system::error_code& error, std::list<AcceptorsElement>::iterator it);
};

#endif
