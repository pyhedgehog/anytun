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

#include <sstream>
#include <vector>

#include <iomanip>
#include <iostream>

#include "commandHandler.h"
#include "../buffer.h"
#include "../log.h"
#include "../syncQueue.h"
#include "../syncCommand.h"
#include "../rtpSessionTable.h"
#include "callIdQueue.h"

#define MAX_COMMAND_LENGTH 1000

CommandHandler::CommandHandler(SyncQueue& q, u_int16_t lp,PortWindow & pw) : queue_(q), running_(true), control_sock_(lp), 
                                                             local_address_("0.0.0.0"), local_port_(lp),port_window_(pw)
{
  pthread_create(&thread_, NULL, run, this);
}

CommandHandler::CommandHandler(SyncQueue& q, string la, u_int16_t lp,PortWindow & pw) : queue_(q), running_(true), control_sock_(la, lp), 
                                                                        local_address_(la), local_port_(lp),port_window_(pw)
{
  pthread_create(&thread_, NULL, run, this);
}

CommandHandler::~CommandHandler()
{
  pthread_cancel(thread_);
  pthread_join(thread_, NULL);
}

void* CommandHandler::run(void* s)
{
  CommandHandler* self = reinterpret_cast<CommandHandler*>(s);

  Buffer buf(u_int32_t(MAX_COMMAND_LENGTH));
  try
  {
    string remote_host;
    u_int16_t remote_port;
 
    int len;
    while(1)
    {
      buf.setLength(MAX_COMMAND_LENGTH);
      len = self->control_sock_.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
      buf.setLength(len);

      std::string ret = self->handle(std::string(reinterpret_cast<char*>(buf.getBuf()), buf.getLength())); // TODO: reinterpret is ugly

      cLog.msg(Log::PRIO_DEBUG) << "CommandHandler received Command from " << remote_host << ":" << remote_port 
                                << ", ret='" << ret << "'";

      self->control_sock_.sendTo(ret.c_str(), ret.length(), remote_host, remote_port);
    }
  }
  catch(SocketException &e)
  {
    self->running_ = false;
    pthread_exit(NULL);
  }
  self->running_ = false;
  pthread_exit(NULL);
}

bool CommandHandler::isRunning()
{
  return running_;
}



std::string CommandHandler::handle(std::string command)
{
  istringstream iss(command);
  ostringstream oss;
  std::string cookie;
  std::string cmd;

  iss >> cookie;
  oss << cookie << " ";

  if(iss.bad() || iss.eof()) {
    oss << RET_ERR_SYNTAX;
    return oss.str();
  }
  iss >> cmd;

  std::vector<std::string> params;
  while(!iss.bad() && !iss.eof()) {
    std::string tmp;
    iss >> tmp;
    params.push_back(tmp);
  }

  switch(std::toupper(cmd[0]))
  {
  case CMD_REQUEST:
    if(params.size() < 4) { oss << RET_ERR_SYNTAX; break; }
    oss << handleRequest(cmd.erase(0,1), params[0], params[1], params[2], params[3], (params.size() < 5) ? "" : params[4]);
    break;
  case CMD_RESPONSE:
    if(params.size() < 4) { oss << RET_ERR_SYNTAX; break; }
    oss << handleResponse(cmd.erase(0,1), params[0], params[1], params[2], params[3], (params.size() < 5) ? "" : params[4]);
    break;
  case CMD_DELETE:
    if(params.size() < 2) { oss << RET_ERR_SYNTAX; break; }
    oss << handleDelete(params[0], params[1], (params.size() < 3) ? "" : params[2]);
    break;
  case CMD_VERSION:
    if(cmd.length() > 1 && cmd[1] == 'F') {
      if(params.size() < 1) { oss << RET_ERR_SYNTAX; break; }
      oss << handleVersionF(params[0]);
      break;
    }
    oss << handleVersion();
    break;
  case CMD_INFO:
    oss << handleInfo();
    break;
  default:
    oss << RET_ERR_SYNTAX;
    break;
  }

  return oss.str();
}

string CommandHandler::handleRequest(string modifiers, string call_id, string addr, string port, string from_tag, string to_tag)
{
  std::cout << "received request[" << modifiers << "] command ('" << call_id << "','" << addr  << "','" << port 
            << "','" << from_tag << "','" << to_tag << "')" << std::endl;

  try 
  {
    bool is_new;
    RtpSession& session = gRtpSessionTable.getOrNewSession(call_id, is_new);
    if(is_new)
    {
      static u_int16_t port1 = 35000; // TODO: get next available port
      static u_int16_t port2 = 35001; // TODO: get next available port
      port1+=2;
			port2+=2;

      session.setLocalAddr("0.0.0.0"); // TODO: read this from config
      session.setLocalPort1(port1);
      session.setLocalPort2(port2);
    }
    istringstream iss(port);
    u_int16_t rport;
    iss >> rport;
    session.setRemotePort1(rport);
    session.setRemoteAddr1(addr);
    SyncCommand sc(call_id);
    queue_.push(sc);

    ostringstream oss;
    oss << session.getLocalPort2();
    return oss.str();
  }
  catch(std::exception& e)
  {
    return RET_ERR_UNKNOWN; // TODO: change to corret error value
  }
}

string CommandHandler::handleResponse(string modifiers, string call_id, string addr, string port, string from_tag, string to_tag)
{
  std::cout << "received response[" << modifiers << "] command ('" << call_id << "','" << addr  << "','" << port 
            << "','" << from_tag << "','" << to_tag << "')" << std::endl;

  try
  {
    RtpSession& session = gRtpSessionTable.getSession(call_id);
    istringstream iss(port);
    u_int16_t rport;
    iss >> rport;
    session.setRemotePort2(rport);
    session.setRemoteAddr2(addr);
    session.isComplete(true);
    SyncCommand sc(call_id);
    queue_.push(sc);

    gCallIdQueue.push(call_id);

    ostringstream oss;
    oss << session.getLocalPort1();
    return oss.str();
  }
  catch(std::exception& e)
  {
    return RET_ERR_UNKNOWN; // TODO: change to corret error value
  }
}

string CommandHandler::handleDelete(string call_id, string from_tag, string to_tag)
{
  std::cout << "received delete command ('" << call_id << "','" << from_tag << "','" << to_tag << "')" << std::endl;

  try
  {
    RtpSession& session = gRtpSessionTable.getSession(call_id);
    session.isDead(true);
    SyncCommand sc(call_id);
    queue_.push(sc);

    return RET_OK;
  }
  catch(std::exception& e)
  {
    return RET_ERR_UNKNOWN; // TODO: change to corret error value
  }
}

string CommandHandler::handleVersion()
{
  std::cout << "received version command" << std::endl;  
  return BASE_VERSION;
}

string CommandHandler::handleVersionF(string date_code)
{
  std::cout << "received version[F] command ('" << date_code << "')" << std::endl;  
  if(!date_code.compare(SUP_VERSION))
    return "1";
  
  return "0";
}

string CommandHandler::handleInfo()
{
  std::cout << "received info command, ignoring" << std::endl;  
  return RET_OK;
}

