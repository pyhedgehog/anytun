#ifndef _SYNCTCPCONNECTION_H_
#define _SYNCTCPCONNECTION_H_
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>

#include <string>

class SyncTcpConnection
  : public boost::enable_shared_from_this<SyncTcpConnection>
{
public:
  typedef boost::shared_ptr<SyncTcpConnection> pointer;
  static pointer create(boost::asio::io_service& io_service)
	{
	   return pointer(new SyncTcpConnection(io_service));
	};
	boost::function<void(SyncTcpConnection *)> onConnect;
  boost::asio::ip::tcp::socket& socket();
  void start();
	void Send(std::string message);
private:
  SyncTcpConnection(boost::asio::io_service& io_service);

  void handle_write(const boost::system::error_code & /*error*/,
      size_t /*bytes_transferred*/);
  boost::asio::ip::tcp::socket socket_;
};
#endif
