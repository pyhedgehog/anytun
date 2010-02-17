/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl,
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <sstream>
#include <iostream>
#include <string>
#include "connectionList.h"
#include "syncCommand.h"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


#include "log.h"
#include "syncClient.h"
#include "syncTcpConnection.h"
#include "buffer.h"
#include <boost/array.hpp>


SyncClient::SyncClient(std::string hostname,std::string port)
  :hostname_(hostname),port_(port)
{
}

void SyncClient::run()
{
  bool connected(false);
  for(;;) {
    try {
      boost::asio::io_service io_service;
      SyncTcpConnection::proto::resolver resolver(io_service);
      SyncTcpConnection::proto::resolver::query query(hostname_, port_);
      SyncTcpConnection::proto::resolver::iterator endpoint_iterator = resolver.resolve(query);
      SyncTcpConnection::proto::resolver::iterator end;

      SyncTcpConnection::proto::socket socket(io_service);
      boost::system::error_code error = boost::asio::error::host_not_found;
      while(error && endpoint_iterator != end) {
        socket.close();
        socket.connect(*endpoint_iterator++, error);
      }
      if(error) {
        throw boost::system::system_error(error);
      }
      if(!connected) {
        cLog.msg(Log::PRIO_NOTICE) << "sync: connected to " << hostname_ <<":"<< port_;
      }
      connected=true;
      readAndProcess(socket); //endless loop
    } catch(std::exception& e) {
      if(connected) {
        cLog.msg(Log::PRIO_NOTICE) << "sync: connection to " << hostname_ <<":"<< port_<< " lost ("<< e.what() << ") retrying every 10sec";
      }
      connected=false;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10000));
    }
  }
}

void SyncClient::readAndProcess(SyncTcpConnection::proto::socket& socket)
{
  ConnectionList& cl_(gConnectionList);
  size_t message_lenght ;
  for(;;) {
    std::stringstream message_lenght_stream;
    readExactly(socket,5,message_lenght_stream);
    message_lenght_stream >> message_lenght;
    std::stringstream void_stream;
    readExactly(socket,1,void_stream); //skip space
    std::stringstream sync_command_stream;
    readExactly(socket,message_lenght, sync_command_stream);
    //cLog.msg(Log::PRIO_NOTICE) << "recieved sync inforamtaion "<<tmp.str()<< std::endl;
    boost::archive::text_iarchive ia(sync_command_stream);
    SyncCommand scom(cl_);
    ia >> scom;
  }
}

void SyncClient::readExactly(SyncTcpConnection::proto::socket& socket,size_t toread, std::iostream& result)
{
  size_t hasread = 0;
  while(toread > hasread) {
    //TODO read bigger buffers
    boost::array<char, 1> buf;
    boost::system::error_code error;
    size_t len = socket.read_some(boost::asio::buffer(buf), error);
    if(error == boost::asio::error::eof) {
      break;  // Connection closed cleanly by peer.
    } else if(error) {
      throw boost::system::system_error(error);  // Some other error.
    }
    //for (size_t pos=0; pos<len; pos++)
    result<<buf[0];
    hasread+=len;
  }
}
