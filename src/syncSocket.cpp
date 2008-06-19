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
#include <sstream>
#include <iostream>
#include <string>
#include "routingTable.h"
#include "rtpSessionTable.h"
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
#include "Sockets/Utility.h"
#include "syncSocket.h"
#include "syncCommand.h"
#include "buffer.h"
//#include "log.h"

SyncSocket::SyncSocket(ISocketHandler& h,ConnectionList & cl)
:TcpSocket(h),cl_(cl)
{
	SetConnectTimeout(12);
}



void SyncSocket::OnAccept()
{
//	Send( Utility::GetLocalHostname() + "\n");
//	Send( Utility::GetLocalAddress() + "\n");
//	Send("Number of sockets in list : " + Utility::l2string(Handler().GetCount()) + "\n");
//	Send("\n");
	//TODO Locking here
	ConnectionMap::iterator cit = cl_.getBeginUnlocked();
  for (;cit!=cl_.getEndUnlocked();++cit)
	{
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const SyncCommand scom(cl_,cit->first);
		oa << scom;
		std::stringstream lengthout;
		lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
		Send(lengthout.str());
		Send(sout.str());
	}
	//TODO Locking here
	RoutingMap::iterator it = gRoutingTable.getBeginUnlocked();
  for (;it!=gRoutingTable.getEndUnlocked();++it)
  {
    NetworkPrefix tmp(it->first);
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const SyncCommand scom(tmp);
		oa << scom;
		std::stringstream lengthout;
		lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
		Send(lengthout.str());
		Send(sout.str());
	}
	//TODO Locking here
	RtpSessionMap::iterator rit = gRtpSessionTable.getBeginUnlocked();
  for (;rit!=gRtpSessionTable.getEndUnlocked();++rit)
  {
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const SyncCommand scom(rit->first);
		oa << scom;
		std::stringstream lengthout;
		lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
		Send(lengthout.str());
		Send(sout.str());
	}
}

//void StatusSocket::InitSSLServer()
//{
//	InitializeContext("server.pem", "keypwd", SSLv23_method());
//}
//
//
//void StatusSocket::Init()
//{
//	EnableSSL();
//}
