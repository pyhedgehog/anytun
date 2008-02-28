#ifndef _MUXSOCKET_H
#define _MUXSOCKET_H

#include "Sockets/TcpSocket.h"
#include "Sockets/ISocketHandler.h"

#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE

class MuxSocket : public TcpSocket
{
public:
	MuxSocket(ISocketHandler& );

	void OnAccept();
//	void Init();

//	void InitSSLServer();
};


#endif // _SYNCSOCKET_H
