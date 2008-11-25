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

#ifndef _ANY_CTR_OPTIONS_H_
#define _ANY_CTR_OPTIONS_H_

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include <list>

class Options
{
public:
  static Options& instance();

  bool parse(int argc, char* argv[]);
  void printUsage();
  void printOptions();

  std::string getProgname();
  Options& setProgname(std::string p);
  bool getDaemonize();
  Options& setDaemonize(bool d);
  bool getChroot();
  Options& setChroot(bool b);
  std::string getUsername();
  Options& setUsername(std::string u);
  std::string getChrootDir();
  Options& setChrootDir(std::string c);
  std::string getPidFile();
  Options& setPidFile(std::string p);
  std::string getFileName();
  Options& setFileName(std::string f);
  std::string getBindToAddr();
  Options& setBindToAddr(std::string b);
  std::string getBindToPort();
  Options& setBindToPort(std::string b);


private:
  Options();
  ~Options();
  Options(const Options &l);
  void operator=(const Options &l);

  static Options* inst;
  static Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(Options::inst != 0)
        delete Options::inst;
    }
  };
  friend class instanceCleaner;

  bool splitAndSetHostPort(std::string hostPort);

  Mutex mutex;

	std::string bind_to_addr_;
	std::string bind_to_port_;
  std::string progname_;
  bool daemonize_;
  bool chroot_;
  std::string username_;
  std::string chroot_dir_;
  std::string pid_file_;
  std::string file_name_;
};

extern Options& gOpt;

#endif
