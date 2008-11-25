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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
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
#include <vector>

#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/bind.hpp>

#include "commandHandler.h"
#include "../buffer.h"
#include "../log.h"
#include "../syncQueue.h"
#include "../syncCommand.h"
#include "../rtpSessionTable.h"
#include "callIdQueue.h"
#include "options.h"

#define MAX_COMMAND_LENGTH 1000

CommandHandler::CommandHandler(SyncQueue& q, std::string lp,PortWindow & pw) : thread_(boost::bind(run,this)), 
                                                                               queue_(q), running_(true), control_sock_(io_service_), 
                                                                               local_address_(""), local_port_(lp),port_window_(pw)
{
  proto::resolver resolver(io_service_);
  proto::resolver::query query(local_port_);  
  proto::endpoint e = *resolver.resolve(query);
  control_sock_.open(e.protocol());
  control_sock_.bind(e);
}

CommandHandler::CommandHandler(SyncQueue& q, string la, std::string lp, PortWindow & pw) : thread_(boost::bind(run,this)), 
                                                                                           queue_(q), running_(true), control_sock_(io_service_), 
                                                                                           local_address_(la), local_port_(lp),port_window_(pw)
{
  proto::resolver resolver(io_service_);
  proto::resolver::query query(local_address_, local_port_);  
  proto::endpoint e = *resolver.resolve(query);
  control_sock_.open(e.protocol());
  control_sock_.bind(e);
}

void CommandHandler::run(void* s)
{
  CommandHandler* self = reinterpret_cast<CommandHandler*>(s);

  Buffer buf(u_int32_t(MAX_COMMAND_LENGTH));
  try
  {
    proto::endpoint remote_end;

    int len;
    while(1)
    {
      buf.setLength(MAX_COMMAND_LENGTH);

      len = self->control_sock_.receive_from(boost::asio::buffer(buf.getBuf(), buf.getLength()), remote_end);
      buf.setLength(len);

      std::string ret = self->handle(std::string(reinterpret_cast<char*>(buf.getBuf()), buf.getLength())); // TODO: reinterpret is ugly

      cLog.msg(Log::PRIO_DEBUG) << "CommandHandler received Command from " << remote_end << ", ret='" << ret << "'";

      self->control_sock_.send_to(boost::asio::buffer(ret.c_str(), ret.length()), remote_end);
    }
  }
  catch(std::exception& e)
  {
    self->running_ = false;
  }
  self->running_ = false;
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
    RtpSession::proto::resolver resolver(io_service_);
    bool is_new;
    RtpSession& session = gRtpSessionTable.getOrNewSession(call_id, is_new);
    if(is_new)
    {
      u_int16_t port1 = port_window_.newPort(); // TODO: get next available port
      u_int16_t port2 = port_window_.newPort(); // TODO: get next available port
			if( !port1 || !port2)
			{
				if( port1) port_window_.freePort(port1);
				if( port2) port_window_.freePort(port2);
				throw std::runtime_error("no free port found");
			}
      std::stringstream ps1, ps2;
      ps1 << port1;
      ps2 << port2;

      RtpSession::proto::endpoint e1, e2;
      if(gOpt.getLocalAddr() == "") {
        RtpSession::proto::resolver::query query1(ps1.str());
        e1 = *resolver.resolve(query1);
        RtpSession::proto::resolver::query query2(ps2.str());
        e2 = *resolver.resolve(query2);
      }
      else {
        RtpSession::proto::resolver::query query1(gOpt.getLocalAddr(),ps1.str());
        e1 = *resolver.resolve(query1);
        RtpSession::proto::resolver::query query2(gOpt.getLocalAddr(),ps2.str());
        e2 = *resolver.resolve(query2);
      }

      session.setLocalEnd1(e1);
      session.setLocalEnd2(e2);
    }
    RtpSession::proto::resolver::query query(addr,port);
    session.setRemoteEnd1(*resolver.resolve(query));

    ostringstream oss;
    oss << session.getLocalEnd2().port();
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
    RtpSession::proto::resolver resolver(io_service_);
    RtpSession::proto::resolver::query query(addr,port);
    session.setRemoteEnd2(*resolver.resolve(query));
    session.isComplete(true);
    SyncCommand sc(call_id);
    queue_.push(sc);

    ostringstream oss;
    oss << session.getLocalEnd1().port();
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

