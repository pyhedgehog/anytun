#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
#include "Sockets/Utility.h"
#include "syncSocket.h"

SyncSocket::SyncSocket(ISocketHandler& h,ConnectionList & cl)
:TcpSocket(h),cl_(cl)
{
	// initial connection timeout setting and number of retries
	SetConnectTimeout(12);
	SetConnectionRetry(5);

	// Also reconnect broken link
//	SetReconnect(true);
}


bool SyncSocket::OnConnectRetry()
{
//	return true;
		return false;
}


void SyncSocket::OnReconnect()
{
	// ...
	//Send("Welcome back\r\n");
}

void SyncSocket::OnAccept()
{
	Send( Utility::GetLocalHostname() + "\n");
	Send( Utility::GetLocalAddress() + "\n");
	Send("Number of sockets in list : " + Utility::l2string(Handler().GetCount()) + "\n");
	Send("\n");
	if( ! cl_.empty())
	{
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const ConnectionParam conn = cl_.getConnection();
		oa << conn;
		Send(sout.str()+"\n");
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
