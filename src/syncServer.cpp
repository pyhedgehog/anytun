#include "syncServer.h"

//using asio::ip::tcp;

SyncServer::SyncServer(boost::asio::io_service& io_service, SyncTcpConnection::proto::endpoint tcp_endpoint )
    : acceptor_(io_service, tcp_endpoint)
{
  start_accept();
}

void SyncServer::start_accept()
{
  Lock lock(mutex_);
  SyncTcpConnection::pointer new_connection =
    SyncTcpConnection::create(acceptor_.io_service());
  conns_.push_back(new_connection);
  
  acceptor_.async_accept(new_connection->socket(),
                         boost::bind(&SyncServer::handle_accept, this, new_connection,
                                     boost::asio::placeholders::error));
}

void SyncServer::send(std::string message)
{
  Lock lock(mutex_);
  for(std::list<SyncTcpConnection::pointer>::iterator it = conns_.begin() ;it != conns_.end(); ++it) {
    (*it)->Send(message);
  }
}

void  SyncServer::handle_accept(SyncTcpConnection::pointer new_connection,
    const boost::system::error_code& error)
{
  if (!error)
  {
    new_connection->onConnect=onConnect;
    new_connection->start();
    start_accept();
  }
}
