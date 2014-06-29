/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _COMMAND_HANDLER_H_
#define _COMMAND_HANDLER_H_

#include <boost/asio.hpp>

#include <string>
#include "../datatypes.h"
#include "../PracticalSocket.h"
#include "../syncQueue.h"
#include "portWindow.h"

class CommandHandler
{
public:
  typedef boost::asio::ip::udp proto;

  CommandHandler(SyncQueue& q, std::string lp, PortWindow&);
  CommandHandler(SyncQueue& q, std::string la, std::string lp, PortWindow&);

  bool isRunning();

#define CMD_REQUEST 'U'
#define CMD_RESPONSE 'L'
#define CMD_DELETE 'D'
#define CMD_VERSION 'V'
#define CMD_INFO 'I'

#define RET_OK "0"
#define RET_ERR_SYNTAX "E1"
#define RET_ERR_UNKNOWN "E2"

#define BASE_VERSION "20040107"
#define SUP_VERSION "20050322"

private:
  CommandHandler(const CommandHandler& c);
  void operator=(const CommandHandler& c);

  static void run(void* s);
  std::string handle(std::string command);

  std::string handleRequest(std::string modifiers, std::string call_id, std::string addr, std::string port, std::string from_tag, std::string to_tag);
  std::string handleResponse(std::string modifiers, std::string call_id, std::string addr, std::string port, std::string from_tag, std::string to_tag);
  std::string handleDelete(std::string call_id, std::string from_tag, std::string to_tag);
  std::string handleVersion();
  std::string handleVersionF(std::string date_code);
  std::string handleInfo();

  boost::thread thread_;
  SyncQueue& queue_;

  bool running_;
  boost::asio::io_service io_service_;
  proto::socket control_sock_;
  std::string local_address_;
  std::string local_port_;
  PortWindow& port_window_;
};


#endif
