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
#include "options.h"
#include "resolver.h"

#include "syncServer.h"
#include "daemon.hpp"

void syncOnConnect(SyncTcpConnection * connptr)
{
  std::ifstream file(gOpt.getFileName().c_str());
  if(file.is_open()) {
    std::string line;
    while (!file.eof()) {
      getline (file,line);
      connptr->Send(line);
    }
    file.close();
  }
}

void syncListener()
{
 boost::asio::io_service io_service;
  try
  {
    SyncServer server(gOpt.getBindToAddr(), gOpt.getBindToPort(), boost::bind(syncOnConnect, _1));
    server.run();
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught runtime_error: " << e.what();
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught exception: " << e.what();
  }
}

int main(int argc, char* argv[])
{
  bool daemonized=false;
  try 
  {
    try 
    {
      bool result = gOpt.parse(argc, argv);
      if(!result) {
        gOpt.printUsage();
        exit(0);
      }
      StringList targets = gOpt.getLogTargets();
      if(targets.empty()) {
        cLog.addTarget("syslog:3,anytun-controld,daemon");
      }
      else {
        StringList::const_iterator it;
        for(it = targets.begin();it != targets.end(); ++it)
          cLog.addTarget(*it);
      }
    }
    catch(syntax_error& e)
    {
      std::cerr << e << std::endl;
      gOpt.printUsage();
      exit(-1);
    }
       
    cLog.msg(Log::PRIO_NOTICE) << "anytun-controld started..."; 
    gOpt.parse_post(); // print warnings


    std::ifstream file( gOpt.getFileName().c_str() );
    if( file.is_open() )
      file.close();
    else {
      std::cout << "ERROR: unable to open file!" << std::endl;
      exit(-1);
    }
    
    PrivInfo privs(gOpt.getUsername(), gOpt.getGroupname());
    if(gOpt.getDaemonize()) {
      daemonize();
      daemonized = true;
    }

    gSignalController.init();
    gResolver.init();
    
    if(gOpt.getChrootDir() != "")
      do_chroot(gOpt.getChrootDir());
    
    privs.drop();

    boost::thread * syncListenerThread;
    syncListenerThread = new boost::thread(boost::bind(syncListener));
    
    int ret = gSignalController.run();
    
    return ret;
  }
  catch(std::runtime_error& e)
  {
    if(daemonized)
      cLog.msg(Log::PRIO_ERROR) << "uncaught runtime error, exiting: " << e.what();
    else
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
  }
  catch(std::exception& e)
  {
    if(daemonized)
      cLog.msg(Log::PRIO_ERROR) << "uncaught exception, exiting: " << e.what();
    else
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
  }
}

