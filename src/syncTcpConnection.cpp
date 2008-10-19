#include "syncTcpConnection.h"
#include <boost/bind.hpp>
#include <asio.hpp>

#include <sstream>
#include <iostream>
#include <string>
#include "routingTable.h"
#include "rtpSessionTable.h"
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "syncCommand.h"
#include "buffer.h"

  asio::ip::tcp::socket& SyncTcpConnection::socket()
  {
    return socket_;
  }

void SyncTcpConnection::start()
{
	ConnectionList & cl_(gConnectionList);
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
	//TODO Locking here
	RtpSessionMap::iterator rit = gRtpSessionTable.getBeginUnlocked();
	for (;rit!=gRtpSessionTable.getEndUnlocked();++rit)
	{
		std::ostringstream sout;
		boost::archive::text_oarchive oa(sout);
		const SyncCommand scom(rit->first);
		oa << scom;
		std::stringstream lengthout;
		lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
		Send(lengthout.str());
		Send(sout.str());
	}
}
void SyncTcpConnection::Send(std::string message)
{
    asio::async_write(socket_, asio::buffer(message),
        boost::bind(&SyncTcpConnection::handle_write, shared_from_this(),
          asio::placeholders::error,
          asio::placeholders::bytes_transferred));
}
SyncTcpConnection::SyncTcpConnection(asio::io_service& io_service)
	: socket_(io_service)
{
}

void SyncTcpConnection::handle_write(const asio::error_code& /*error*/,
		size_t /*bytes_transferred*/)
{
}
