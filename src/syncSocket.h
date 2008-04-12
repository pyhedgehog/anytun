#ifndef _SYNCSOCKET_H
#define _SYNCSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"
#include "connectionList.h"

#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE

class SyncSocket : public TcpSocket
{
public:
	SyncSocket(ISocketHandler&,ConnectionList & );

	void OnAccept();
//	void Init();

//	void InitSSLServer();
private:
	ConnectionList & cl_;
};


#endif // _SYNCSOCKET_H
