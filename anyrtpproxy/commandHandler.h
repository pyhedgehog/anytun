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
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _COMMAND_HANDLER_H_
#define _COMMAND_HANDLER_H_

#include <string>
#include "../datatypes.h"
#include "../PracticalSocket.h"

using std::string;

class CommandHandler
{
public:
  CommandHandler(u_int16_t lp);
  CommandHandler(string la, u_int16_t lp);
  ~CommandHandler();
  
  bool isRunning();

  #define CMD_REQUEST 'U'
  #define CMD_RESPONSE 'L'
  #define CMD_DELETE 'D'
  #define CMD_VERSION 'V'
  #define CMD_INFO 'I'

  #define RET_OK "0"
  #define RET_ERR_SYNTAX "E1"

  #define BASE_VERSION "20040107"
  #define SUP_VERSION "20050322"

private:
  CommandHandler(const CommandHandler &c);
  void operator=(const CommandHandler &c);

  static void* run(void* s);
  string handle(string command);
  
  string handleRequest(string modifiers, string call_id, string addr, string port, string from_tag, string to_tag);
  string handleResponse(string modifiers, string call_id, string addr, string port, string from_tag, string to_tag);
  string handleDelete(string call_id, string from_tag, string to_tag);
  string handleVersion();
  string handleVersionF(string date_code);
  string handleInfo();

  pthread_t thread_;
  bool running_;
  UDPSocket control_sock_;
  string local_address_;
  u_int16_t local_port_;
};


#endif
