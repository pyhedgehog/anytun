#ifndef _SYNCSOCKET_H
#define _SYNCSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"

#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE

class SyncSocket : public TcpSocket
{
public:
	SyncSocket(ISocketHandler& );

	void OnAccept();

	bool OnConnectRetry();
	void OnReconnect();
//	void Init();

//	void InitSSLServer();
//private:
//	ResumeSocket2& operator=(const ResumeSocket2& ) { return *this; } // assignment operator
};


#endif // _SYNCSOCKET_H
