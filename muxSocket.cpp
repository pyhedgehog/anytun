#include <sstream>
#include <iostream>
#include <string>

#include "Sockets/Utility.h"
#include "muxSocket.h"
//#include "log.h"

#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE


MuxSocket::MuxSocket(ISocketHandler& h)
:TcpSocket(h)
{
	SetConnectTimeout(12);
}



void MuxSocket::OnAccept()
{
	Send( Utility::GetLocalHostname() + "\n");
	Send( Utility::GetLocalAddress() + "\n");
	Send("Number of sockets in list : " + Utility::l2string(Handler().GetCount()) + "\n");
	Send("\n");
	//TODO Locking here
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
