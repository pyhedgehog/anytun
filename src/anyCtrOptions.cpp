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
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <queue>
#include <string>
#include <sstream>

#include "datatypes.h"
#include "anyCtrOptions.h"

Options* Options::inst = NULL;
Mutex Options::instMutex;
Options& gOpt = Options::instance();

Options& Options::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst)
    inst = new Options();
  
  return *inst;
}

Options::Options()
{
  progname_ = "anytun-controld";
  file_name_ = "";
  daemonize_ = true;
  chroot_ = false;
  username_ = "nobody";
  chroot_dir_ = "/var/run/anytun-controld";
  pid_file_ = "";
  bind_to_addr_ = "127.0.0.1";
  bind_to_port_ = 4445;
}

Options::~Options()
{
}

#define PARSE_BOOL_PARAM(SHORT, LONG, VALUE)             \
    else if(str == SHORT || str == LONG)                 \
      VALUE = true;

#define PARSE_INVERSE_BOOL_PARAM(SHORT, LONG, VALUE)     \
    else if(str == SHORT || str == LONG)                 \
      VALUE = false;

#define PARSE_SCALAR_PARAM(SHORT, LONG, VALUE)           \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      std::stringstream tmp;                             \
      tmp << argv[i+1];                                  \
      tmp >> VALUE;                                      \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_SCALAR_PARAM2(SHORT, LONG, VALUE1, VALUE2) \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 2 ||                                     \
         argv[i+1][0] == '-' || argv[i+2][0] == '-')     \
        return false;                                    \
      std::stringstream tmp;                             \
      tmp << argv[i+1] << " " << argv[i+2];              \
      tmp >> VALUE1;                                     \
      tmp >> VALUE2;                                     \
      argc-=2;                                           \
      i+=2;                                              \
    }

#define PARSE_HEXSTRING_PARAM_SEC(SHORT, LONG, VALUE)    \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      VALUE = Buffer(std::string(argv[i+1]));            \
      for(size_t j=0; j < strlen(argv[i+1]); ++j)        \
        argv[i+1][j] = '#';                              \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_CSLIST_PARAM(SHORT, LONG, LIST)            \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      std::stringstream tmp(argv[i+1]);                  \
			while (tmp.good())                                 \
			{                                                  \
				std::string tmp_line;                            \
				getline(tmp,tmp_line,',');                       \
				LIST.push(tmp_line);                             \
			}                                                  \
      argc--;                                            \
      i++;                                               \
    }

bool Options::parse(int argc, char* argv[])
{
  Lock lock(mutex);

  progname_ = argv[0];
  argc--;

  std::string control_host("");
  for(int i=1; argc > 0; ++i)
  {
    std::string str(argv[i]);
    argc--;

    if(str == "-h" || str == "--help")
      return false;
    PARSE_SCALAR_PARAM("-f","--file", file_name_)
    PARSE_INVERSE_BOOL_PARAM("-D","--nodaemonize", daemonize_)
    PARSE_BOOL_PARAM("-C","--chroot", chroot_)
    PARSE_SCALAR_PARAM("-u","--username", username_)
    PARSE_SCALAR_PARAM("-H","--chroot-dir", chroot_dir_)
    PARSE_SCALAR_PARAM("-P","--write-pid", pid_file_)
    PARSE_SCALAR_PARAM("-X","--control-host", control_host)
    else 
      return false;
  }

  if(control_host != "") {
		std::stringstream tmp_stream(control_host);
		getline(tmp_stream,bind_to_addr_,':');
		if(!tmp_stream.good())
			return false;
		tmp_stream >> bind_to_port_;
  }

  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;
  std::cout << "anytun-controld [-h|--help]                  prints this..." << std::endl;
  std::cout << "                [-D|--nodaemonize]           don't run in background" << std::endl;
  std::cout << "                [-C|--chroot]                chroot and drop privileges" << std::endl;
  std::cout << "                [-u|--username] <username>   if chroot change to this user" << std::endl;
  std::cout << "                [-H|--chroot-dir] <path>     chroot to this directory" << std::endl;
  std::cout << "                [-P|--write-pid] <path>      write pid to this file" << std::endl;
  std::cout << "                [-f|--file] <path>           path to file" << std::endl;
  std::cout << "                [-X|--control-host] <host:port>  local tcp port to bind to" << std::endl;

}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "daemonize=" << daemonize_ << std::endl;
  std::cout << "chroot=" << chroot_ << std::endl;
  std::cout << "username='" << username_ << "'" << std::endl;
  std::cout << "chroot_dir='" << chroot_dir_ << "'" << std::endl;
  std::cout << "pid_file='" << pid_file_ << "'" << std::endl;
}

std::string Options::getProgname()
{
  Lock lock(mutex);
  return progname_;
}


Options& Options::setProgname(std::string p)
{
  Lock lock(mutex);
  progname_ = p;
  return *this;
}

bool Options::getDaemonize()
{
  return daemonize_;
}

Options& Options::setDaemonize(bool d)
{
  daemonize_ = d;
  return *this;
}

bool Options::getChroot()
{
  return chroot_;
}

Options& Options::setChroot(bool c)
{
  chroot_ = c;
  return *this;
}

std::string Options::getUsername()
{
  Lock lock(mutex);
  return username_;
}

Options& Options::setUsername(std::string u)
{
  Lock lock(mutex);
  username_ = u;
  return *this;
}

std::string Options::getChrootDir()
{
  Lock lock(mutex);
  return chroot_dir_;
}

Options& Options::setChrootDir(std::string c)
{
  Lock lock(mutex);
  chroot_dir_ = c;
  return *this;
}

std::string Options::getPidFile()
{
  Lock lock(mutex);
  return pid_file_;
}

Options& Options::setPidFile(std::string p)
{
  Lock lock(mutex);
  pid_file_ = p;
  return *this;
}

std::string Options::getFileName()
{
  Lock lock(mutex);
  return file_name_;
}

Options& Options::setFileName(std::string f)
{
  Lock lock(mutex);
  file_name_ = f;
  return *this;
}

std::string Options::getBindToAddr()
{
  Lock lock(mutex);
  return bind_to_addr_;
}

Options& Options::setBindToAddr(std::string b)
{
  Lock lock(mutex);
  bind_to_addr_ = b;
  return *this;
}

uint16_t Options::getBindToPort()
{
  return bind_to_port_;  
}

Options& Options::setBindToPort(uint16_t b)
{
  bind_to_port_ = b;
  return *this;
}
