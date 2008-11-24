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
#include "syncClient.h"
#include "buffer.h"
#include <boost/array.hpp>


SyncClient::SyncClient(std::string hostname,std::string port)
:hostname_( hostname),port_(port)
{
}

void SyncClient::run()
{
  try
  {
    boost::asio::io_service io_service;
		for(;;)
		{
			boost::asio::ip::tcp::resolver resolver(io_service);
			boost::asio::ip::tcp::resolver::query query( hostname_, port_);
			boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
			boost::asio::ip::tcp::resolver::iterator end;

			boost::asio::ip::tcp::socket socket(io_service);
			boost::system::error_code error = boost::asio::error::host_not_found;
			while (error && endpoint_iterator != end)
			{
				socket.close();
				socket.connect(*endpoint_iterator++, error);
			}
			if (error)
				throw boost::system::system_error(error);

			for (;;)
			{
				boost::array<char, 128> buf;
				boost::system::error_code error;

				size_t len = socket.read_some(boost::asio::buffer(buf), error);

				if (error == boost::asio::error::eof)
					break; // Connection closed cleanly by peer.
				else if (error)
					throw boost::system::system_error(error); // Some other error.

				OnRawData(buf.data(), len);
			}
		}
		sleep(10);
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
  }
}

void SyncClient::OnRawData(const char *buf,size_t len)
//void SyncClientSocket::OnLine(const std::string& line)
{
	ConnectionList & cl_ (gConnectionList);
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
