#ifndef _SYNC_SERVER_H_
#define _SYNC_SERVER_H_
//#include <iostream>
//#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>

#include <asio.hpp>
#include <list>
#include "syncTcpConnection.h"

//using boost::asio::ip::tcp;

class SyncServer
{
public:
  SyncServer(asio::io_service& io_service,  asio::ip::tcp::endpoint tcp_endpoint );
	boost::function<void(SyncTcpConnection *)> onConnect;
  std::list<SyncTcpConnection::pointer> conns_;
	void send(std::string message);
private:
  void start_accept();
  void handle_accept(SyncTcpConnection::pointer new_connection,
      const asio::error_code& error);

  asio::ip::tcp::acceptor acceptor_;
};
#endif
