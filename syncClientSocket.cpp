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
:TcpSocket(h),cl_(cl),missing_chars(-1)
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
		std::cout << buf[index];
		iss_ << buf[index];
	}
	while (iss_.good())
	{
		if(missing_chars==-1 && iss_.str().size()>5)
		{
      char * buffer = new char [6];
      iss_.read(buffer,6);
      std::stringstream tmp;
      tmp.write(buffer,6);
			tmp>>missing_chars;
			cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion from " << GetRemoteHostname() <<" "<<tmp.str()<<"bytes of data"<< std::endl;
			delete buffer;
		} else
		if(missing_chars>0 && missing_chars<=static_cast<int32_t>(iss_.str().size()))
		{
			char * buffer = new char [missing_chars];
			iss_.read(buffer,missing_chars);
			std::stringstream tmp;
			tmp.write(buffer,missing_chars);
			cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion from " << GetRemoteHostname() <<" \""<<tmp.str()<<'"'<< std::endl;
			boost::archive::text_iarchive ia(tmp);
			SyncCommand scom(cl_);
			ia >> scom;
			missing_chars=-1;
			delete buffer;
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
