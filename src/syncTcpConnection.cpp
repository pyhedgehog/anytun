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
  onConnect(this);
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
