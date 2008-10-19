#include "syncServer.h"

//using asio::ip::tcp;

SyncServer::SyncServer(asio::io_service& io_service, asio::ip::tcp::endpoint tcp_endpoint )
    : acceptor_(io_service, tcp_endpoint)
{
	start_accept();
}

void SyncServer::start_accept()
{
	SyncTcpConnection::pointer new_connection =
		SyncTcpConnection::create(acceptor_.io_service());
  conns_.push_back(new_connection);

	acceptor_.async_accept(new_connection->socket(),
			boost::bind(&SyncServer::handle_accept, this, new_connection,
				asio::placeholders::error));
}

void  SyncServer::handle_accept(SyncTcpConnection::pointer new_connection,
		const asio::error_code& error)
{
	if (!error)
	{
		new_connection->start();
		start_accept();
	}
}
