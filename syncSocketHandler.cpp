//#include <sstream>
//#include <iostream>
//#include <string>
//
//#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/text_iarchive.hpp>


//#include "connectionParam.h"
//#include "Sockets/Utility.h"
#include "syncSocketHandler.h"
#include "syncListenSocket.h"
#include "syncSocket.h"
#include "connectionList.h"
//#include "buffer.h"
//#include "log.h"

SyncSocketHandler::SyncSocketHandler(SyncQueue & queue)
:SocketHandler(),queue_(queue)
{
}

int SyncSocketHandler::Select(long sec,long usec)
{
	if(!queue_.empty())
	{
		std::string sendstr = queue_.pop();
		for (socket_m::iterator it = m_sockets.begin(); it != m_sockets.end(); it++)
		{
			Socket *p = (*it).second;
			TcpSocket *p3 = dynamic_cast<TcpSocket *>(p);
			//SyncListenSocket<SyncSocket,ConnectionList> *p4 = dynamic_cast<SyncListenSocket<SyncSocket,ConnectionList> *>(p);
			p3->Send(sendstr);
		}
	}
	return SocketHandler::Select(sec,usec);
}
