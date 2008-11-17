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

#include <iostream>
#include <fstream>
#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <string>

#include "datatypes.h"

#include "log.h"
#include "signalController.h"
#include "anyCtrOptions.h"

#include "syncServer.h"
#include "daemon.hpp"

std::string filename;

class ThreadParam
{
public:
  ThreadParam() : addr(""), port(0) {};
  std::string addr;
  u_int16_t port;
};

void syncOnConnect(SyncTcpConnection * connptr)
{
  std::ifstream file( filename.c_str() );
  if( file.is_open() )
	{
	   std::string line;
		 while (! file.eof() )
		 {
		   getline (file,line);
			 connptr->Send(line);
		 }
	 file.close();
	}
}

void syncListener(void* p )
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

  try
  {
    asio::io_service io_service;
    SyncServer server(io_service,asio::ip::tcp::endpoint(asio::ip::tcp::v6(), param->port));
		server.onConnect=boost::bind(syncOnConnect,_1);
    io_service.run();
  }
  catch (std::exception& e)
  {
    std::cerr << e.what() << std::endl;
  }

}

int main(int argc, char* argv[])
{
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }
  
  std::ifstream file( gOpt.getFileName().c_str() );
  if( file.is_open() )
    file.close();
  else
  {
    std::cout << "ERROR: unable to open file!" << std::endl;
    exit(-1);
  }

  std::ofstream pidFile;
  if(gOpt.getPidFile() != "") {
    pidFile.open(gOpt.getPidFile().c_str());
    if(!pidFile.is_open()) {
      std::cout << "can't open pid file" << std::endl;
    }
  }
  
  if(gOpt.getChroot())
    chrootAndDrop(gOpt.getChrootDir(), gOpt.getUsername());
  if(gOpt.getDaemonize())
    daemonize();

  if(pidFile.is_open()) {
    pid_t pid = getpid();
    pidFile << pid;
    pidFile.close();
  }

  SignalController sig;
  sig.init();

  ThreadParam p;
  p.addr = gOpt.getBindToAddr();
  p.port = gOpt.getBindToPort(); 
  filename =  gOpt.getFileName(); 
  boost::thread * syncListenerThread;
  syncListenerThread = new boost::thread(boost::bind(syncListener,&p));

	int ret = sig.run();

  return ret;
}

