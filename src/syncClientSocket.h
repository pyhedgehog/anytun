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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _SYNCCLIENTSOCKET_H
#define _SYNCCLIENTSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"
#include "connectionList.h"
#include "syncCommand.h"
#include <sstream>
#include <iostream>
#include <string>



#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE

class SyncClientSocket : public TcpSocket
{
public:
	SyncClientSocket(ISocketHandler&,ConnectionList & );

	bool OnConnectRetry();
	void OnReconnect();
	void OnRawData(const char *buf,size_t len);
private:
	ConnectionList & cl_;
	std::stringstream iss_;
	int32_t missing_chars;
	int32_t buffer_size_;
};


#endif // _SYNCSOCKET_H
