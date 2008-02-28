#include <sstream>
#include <iostream>
#include <string>
#include "routingTable.h"
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
