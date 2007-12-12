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

void SyncSocket::OnRawData(const char *buf,size_t len)
//void SyncSocket::OnLine(const std::string& line)
{
	std::stringstream iss;
	std::cout << "recieved sync inforamtaion:"<< std::endl;
	for(size_t index=0;index<len;index++)
	{
		std::cout << buf[index];
		iss << buf[index];
	}
	boost::archive::text_iarchive ia(iss);
  SeqWindow * seq= new SeqWindow(0);
  seq_nr_t seq_nr_=0;
  KeyDerivation * kd = new KeyDerivation;
  kd->init(::Buffer(20), ::Buffer(14));
  ConnectionParam conn ( (*kd),  (*seq), seq_nr_, "",  0);
	ia >> conn;
  std::cout << "sync connection remote host " << conn.remote_host_ << ":" << conn.remote_port_ << std::endl;
	cl_.clear();
  cl_.addConnection(conn,std::string("default"));
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
