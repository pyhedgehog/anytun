#ifndef _SYNCSOCKETHANDLER_H
#define _SYNCSOCKETHANDLER_H

#include "Sockets/TcpSocket.h"
#include "Sockets/SocketHandler.h"
#include "syncQueue.h"

//#ifdef SOCKETS_NAMESPACE
//using namespace SOCKETS_NAMESPACE;
//#endif // SOCKETS_NAMESPACE

class SyncSocketHandler : public SOCKETS_NAMESPACE::SocketHandler
{
public:
	SyncSocketHandler(SyncQueue & );
	int Select(long sec,long usec);

private:
	SyncQueue & queue_;
};


#endif // _SYNCSOCKET_H
