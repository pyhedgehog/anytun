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
//#include <sstream>
//#include <iostream>
//#include <string>
//
//#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
//#include "Sockets/Utility.h"
#include "syncSocketHandler.h"
#include "syncListenSocket.h"
#include "syncSocket.h"
#include "connectionList.h"
//#include "buffer.h"
//#include "log.h"

SyncSocketHandler::SyncSocketHandler(SyncQueue & queue)
:SocketHandler(),queue_(queue)
{
}

int SyncSocketHandler::Select(long sec,long usec)
{
	if(!queue_.empty())
	{
		std::string sendstr = queue_.pop();
		for (socket_m::iterator it = m_sockets.begin(); it != m_sockets.end(); it++)
		{
			::SOCKETS_NAMESPACE::Socket *p = (*it).second;
			TcpSocket *p3 = dynamic_cast<TcpSocket *>(p);
			//SyncListenSocket<SyncSocket,ConnectionList> *p4 = dynamic_cast<SyncListenSocket<SyncSocket,ConnectionList> *>(p);
			if (p3)
				p3->Send(sendstr);
		}
	}
	return SocketHandler::Select(sec,usec);
}
