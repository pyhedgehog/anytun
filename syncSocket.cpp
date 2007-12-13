#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
#include "Sockets/Utility.h"
#include "syncSocket.h"
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
	if( ! cl_.empty())
	{
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const ConnectionParam conn = cl_.getConnection();
		oa << conn;
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
