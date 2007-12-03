#ifndef _SYNCSOCKET_H
#define _SYNCSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"

using namespace sockets;

class SyncSocket : public TcpSocket
{
public:
	SyncSocket(ISocketHandler& );

	void OnAccept();

	bool OnConnectRetry();
	void OnReconnect();

//private:
//	ResumeSocket2& operator=(const ResumeSocket2& ) { return *this; } // assignment operator
};


#endif // _SYNCSOCKET_H
