
#include "Sockets/Utility.h"
#include "syncSocket.h"


SyncSocket::SyncSocket(ISocketHandler& h)
:TcpSocket(h)
{
	// initial connection timeout setting and number of retries
	SetConnectTimeout(12);
	SetConnectionRetry(5);

	// Also reconnect broken link
	SetReconnect(true);
}


bool SyncSocket::OnConnectRetry()
{
	return true;
}


void SyncSocket::OnReconnect()
{
	// ...
	Send("Welcome back\r\n");
}

void SyncSocket::OnAccept()
{
	Send("Local hostname : " + Utility::GetLocalHostname() + "\n");
	Send("Local address : " + Utility::GetLocalAddress() + "\n");
	Send("Number of sockets in list : " + Utility::l2string(Handler().GetCount()) + "\n");
	Send("\n");
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
