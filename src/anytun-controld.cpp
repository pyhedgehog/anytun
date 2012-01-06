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

#include <iostream>
#include <fstream>
#include <string>

#include "datatypes.h"

#include "log.h"
#include "signalController.h"
#include "options.h"
#include "resolver.h"

#include "syncServer.h"
#if !defined(_MSC_VER) && !defined(MINGW)
# include "daemonService.h"
#else
# include "nullDaemon.h"
#endif
#include <vector>

std::list<std::string> config_;

void syncOnConnect(SyncTcpConnection* connptr)
{
  for(std::list<std::string>::const_iterator it=config_.begin(); it!=config_.end(); ++it) {
    connptr->Send(*it);
  }
}

void syncListener()
{
  boost::asio::io_service io_service;
  try {
    SyncServer server(gOpt.getBindToAddr(), gOpt.getBindToPort(), boost::bind(syncOnConnect, _1));
    server.run();
  } catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught runtime_error: " << e.what();
  } catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "sync listener thread died due to an uncaught exception: " << e.what();
  }
}

int main(int argc, char* argv[])
{
  DaemonService service;
  try {
    try {
      if(!gOpt.parse(argc, argv)) {
        exit(0);
      }

      StringList targets = gOpt.getLogTargets();
      for(StringList::const_iterator it = targets.begin(); it != targets.end(); ++it) {
        cLog.addTarget(*it);
      }
    } catch(syntax_error& e) {
      std::cerr << e << std::endl;
      gOpt.printUsage();
      exit(-1);
    }

    cLog.msg(Log::PRIO_NOTICE) << "anytun-controld started...";
    gOpt.parse_post(); // print warnings


    std::ifstream file(gOpt.getFileName().c_str());
    if(file.is_open()) {
      std::string line;
      while(!file.eof()) {
        getline(file,line);
        config_.push_back(line);
      }
      file.close();
    } else {
      std::cout << "ERROR: unable to open file!" << std::endl;
      exit(-1);
    }

    service.initPrivs(gOpt.getUsername(), gOpt.getGroupname());
    if(gOpt.getDaemonize()) {
      service.daemonize();
    }

    if(gOpt.getChrootDir() != "") {
      service.chroot(gOpt.getChrootDir());
    }
    service.dropPrivs();

    gSignalController.init(service);
    gResolver.init();

    boost::thread* syncListenerThread;
    syncListenerThread = new boost::thread(boost::bind(syncListener));
    if(syncListenerThread) syncListenerThread->detach();

    int ret = gSignalController.run();

    return ret;
  } catch(std::runtime_error& e) {
    if(service.isDaemonized()) {
      cLog.msg(Log::PRIO_ERROR) << "uncaught runtime error, exiting: " << e.what();
    } else {
      std::cout << "uncaught runtime error, exiting: " << e.what() << std::endl;
    }
  } catch(std::exception& e) {
    if(service.isDaemonized()) {
      cLog.msg(Log::PRIO_ERROR) << "uncaught exception, exiting: " << e.what();
    } else {
      std::cout << "uncaught exception, exiting: " << e.what() << std::endl;
    }
  }
}

