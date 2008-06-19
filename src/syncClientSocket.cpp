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
#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "log.h"
//#include "connectionParam.h"
#include "Sockets/Utility.h"
#include "syncClientSocket.h"
#include "buffer.h"


SyncClientSocket::SyncClientSocket(ISocketHandler& h,ConnectionList & cl)
:TcpSocket(h),cl_(cl),missing_chars(-1),buffer_size_(0)
{
	// initial connection timeout setting and number of retries
	SetConnectTimeout(12);
	SetConnectionRetry(-1); //infinite reties

	// Also reconnect broken link
	SetReconnect(true);
}


bool SyncClientSocket::OnConnectRetry()
{
	return true;
}


void SyncClientSocket::OnReconnect()
{
  cLog.msg(Log::PRIO_NOTICE) << "reconnected with " << GetRemoteHostname() << std::endl;
	// ...
	//Send("Welcome back\r\n");
}


void SyncClientSocket::OnRawData(const char *buf,size_t len)
//void SyncClientSocket::OnLine(const std::string& line)
{
	for(size_t index=0;index<len;index++)
	{
//		std::cout << buf[index];
		iss_ << buf[index];
		buffer_size_++;
	}
	while (1)
	{
//		cLog.msg(Log::PRIO_NOTICE) << "buffer size "<< buffer_size_ << " missing_chars " << missing_chars;
		if(missing_chars==-1 && buffer_size_>5)
		{
      char * buffer = new char [6+1];
      iss_.read(buffer,6);
      std::stringstream tmp;
      tmp.write(buffer,6);
			tmp>>missing_chars;
//			cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion length from " << GetRemoteHostname() <<" "<<tmp.str()<<"bytes of data"<< std::endl;
			delete[] buffer;
			buffer_size_-=6;
		} else
		if(missing_chars>0 && missing_chars<=buffer_size_)
		{
			char * buffer = new char [missing_chars+1];
			iss_.read(buffer,missing_chars);
			std::stringstream tmp;
			tmp.write(buffer,missing_chars);
//			cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion from " << GetRemoteHostname() <<" \""<<tmp.str()<<'"'<< std::endl;
			boost::archive::text_iarchive ia(tmp);
			SyncCommand scom(cl_);
			ia >> scom;
			buffer_size_-=missing_chars;
			missing_chars=-1;
			delete[] buffer;
		} else
		break;
	}

	//u_int16_t mux = scom.getMux();
	//const ConnectionParam & conn = cl_.getConnection(mux)->second;
  //cLog.msg(Log::PRIO_NOTICE) << "sync connection #"<<mux<<" remote host " << conn.remote_host_ << ":" << conn.remote_port_ << std::endl;
}

//void StatusClientSocket::InitSSLServer()
//{
//	InitializeContext("server.pem", "keypwd", SSLv23_method());
//}
//
//
//void StatusClientSocket::Init()
//{
//	EnableSSL();
//}
