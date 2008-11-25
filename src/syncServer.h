#ifndef _SYNC_SERVER_H_
#define _SYNC_SERVER_H_
//#include <iostream>
//#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include "threadUtils.hpp"


#include <boost/asio.hpp>
#include <list>
#include "syncTcpConnection.h"

class SyncServer
{
public:
  SyncServer(boost::asio::io_service& io_service, SyncTcpConnection::proto::endpoint tcp_endpoint );
	boost::function<void(SyncTcpConnection *)> onConnect;
  std::list<SyncTcpConnection::pointer> conns_;
	void send(std::string message);
private:
  void start_accept();
  void handle_accept(SyncTcpConnection::pointer new_connection,
      const boost::system::error_code& error);
	Mutex mutex_; //Mutex for list conns_
  SyncTcpConnection::proto::acceptor acceptor_;
};
#endif
