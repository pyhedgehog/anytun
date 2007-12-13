#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
#include "Sockets/Utility.h"
#include "syncClientSocket.h"
#include "buffer.h"
//#include "log.h"

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
	std::cout << "SyncClientSocket::OnConnectRetry" << std::endl;
	return true;
}


void SyncClientSocket::OnReconnect()
{
	std::cout << "SyncClientSocket::OnReconnect" << std::endl;
	// ...
	//Send("Welcome back\r\n");
}


void SyncClientSocket::OnRawData(const char *buf,size_t len)
//void SyncClientSocket::OnLine(const std::string& line)
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
