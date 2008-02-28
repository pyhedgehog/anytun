#ifndef _SYNCCLIENTSOCKET_H
#define _SYNCCLIENTSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"
#include "connectionList.h"
#include "syncCommand.h"
#include <sstream>
#include <iostream>
#include <string>



#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE

class SyncClientSocket : public TcpSocket
{
public:
	SyncClientSocket(ISocketHandler&,ConnectionList & );

	bool OnConnectRetry();
	void OnReconnect();
	void OnRawData(const char *buf,size_t len);
private:
	ConnectionList & cl_;
	std::stringstream iss_;
	int32_t missing_chars;
};


#endif // _SYNCSOCKET_H
