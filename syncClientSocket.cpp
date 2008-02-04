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
:TcpSocket(h),cl_(cl)
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
	std::stringstream iss;
	cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion from " << GetRemoteHostname() << std::endl;
	for(size_t index=0;index<len;index++)
	{
		std::cout << buf[index];
		iss << buf[index];
	}

	boost::archive::text_iarchive ia(iss);
	SyncCommand scom(cl_);
	ia >> scom;
	u_int16_t mux = scom.getMux();
	const ConnectionParam & conn = cl_.getConnection(mux)->second;
  cLog.msg(Log::PRIO_NOTICE) << "sync connection #"<<mux<<" remote host " << conn.remote_host_ << ":" << conn.remote_port_ << std::endl;
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
