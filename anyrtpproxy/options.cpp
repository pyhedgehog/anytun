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

#include <iostream>
#include <queue>
#include <string>
#include <sstream>

#include "options.h"

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
  progname_ = "anyrtpproxy";
  chroot_ = false;
  username_ = "nobody";
  chroot_dir_ = "/var/run";
  daemonize_ = true;
  send_port_ = 22220;
  local_interfaces_.push_back(IfListElement("0.0.0.0", 22221));
  remote_hosts_.push_back(IfListElement("127.0.0.1", 22222));
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

#define PARSE_HEXSTRING_PARAM(SHORT, LONG, VALUE)        \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      VALUE = Buffer(std::string(argv[i+1]));            \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_CSLIST_PARAM(SHORT, LONG, LIST)            \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      std::stringstream tmp(argv[i+1]);                  \
      LIST.clear();                                      \
			while (tmp.good())                                 \
			{                                                  \
				std::string tmp_line;                            \
				getline(tmp,tmp_line,',');                       \
				LIST.push_back(tmp_line);                        \
			}                                                  \
      argc--;                                            \
      i++;                                               \
    }

bool Options::parse(int argc, char* argv[])
{
  Lock lock(mutex);

  progname_ = argv[0];
  argc--;
  for(int i=1; argc > 0; ++i)
  {
    std::string str(argv[i]);
    argc--;

    if(str == "-h" || str == "--help")
      return false;
    PARSE_BOOL_PARAM("-t","--chroot", chroot_)
    PARSE_SCALAR_PARAM("-u","--user", username_)
    PARSE_SCALAR_PARAM("-c","--chroot-dir", chroot_dir_)
    PARSE_INVERSE_BOOL_PARAM("-d","--nodaemonize", daemonize_)
    PARSE_SCALAR_PARAM("-p","--port", send_port_)
    PARSE_CSLIST_PARAM("-l","--listen", local_interfaces_)
    PARSE_CSLIST_PARAM("-r","--hosts", remote_hosts_)
    else 
      return false;
  }
  
  return sanityCheck();
}

bool Options::sanityCheck()
{
  IfList::iterator it=local_interfaces_.begin();
  for(u_int32_t i=0; it != local_interfaces_.end(); ++it, ++i)
    if(!it->port_) it->port_ = 22221;

  it=remote_hosts_.begin();
  for(u_int32_t i=0; it != remote_hosts_.end(); ++it, ++i)
    if(!it->port_) it->port_ = 22222;

  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;
  std::cout << "anyrtpproxy [-h|--help]                                     prints this..." << std::endl;
  std::cout << "            [-t|--chroot]                                   chroot and drop priviledges" << std::endl;
  std::cout << "            [-u|--username] <username>                      in case of chroot run as this user" << std::endl;
  std::cout << "            [-c|--chroot-dir] <directory>                   directory to make a chroot to" << std::endl;
  std::cout << "            [-d|--nodaemonize]                              don't run in background" << std::endl;
  std::cout << "            [-p|--port] <port>                              use this port to send out packets" << std::endl;
  std::cout << "            [-l|--listen] <host[:port]>[,<host>[:<port> ..] a list of local interfaces to listen on" << std::endl;
  std::cout << "            [-r|--hosts] <host[:port]>[,<host>[:<port> ..]  a list of remote hosts to send duplicates to" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "chroot='" << chroot_ << "'" << std::endl;
  std::cout << "username='" << username_ << "'" << std::endl;
  std::cout << "chroot-dir='" << chroot_dir_ << "'" << std::endl;
  std::cout << "daemonize='" << daemonize_ << "'" << std::endl;
  std::cout << "send-port='" << send_port_ << "'" << std::endl;
  std::cout << "local interfaces='";
  IfList::const_iterator it=local_interfaces_.begin();
  for(u_int32_t i=0; it != local_interfaces_.end(); ++it, ++i)
  {
    if(i) std::cout << "','";
    std::cout << it->toString();
  }
  std::cout << "'" << std::endl;
  std::cout << "remote hosts='";
  it=remote_hosts_.begin();
  for(u_int32_t i=0; it != remote_hosts_.end(); ++it, ++i)
  {
    if(i) std::cout << "','";
    std::cout << it->toString();
  }
  std::cout << "'" << std::endl;
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

bool Options::getChroot()
{
  Lock lock(mutex);
  return chroot_;
}

Options& Options::setChroot(bool c)
{
  Lock lock(mutex);
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

bool Options::getDaemonize()
{
  Lock lock(mutex);
  return daemonize_;
}

Options& Options::setDaemonize(bool d)
{
  Lock lock(mutex);
  daemonize_ = d;
  return *this;
}

u_int16_t Options::getSendPort()
{
  Lock lock(mutex);
  return send_port_;
}

Options& Options::setSendPort(u_int16_t p)
{
  Lock lock(mutex);
  send_port_ = p;
  return *this;
}

IfList Options::getLocalInterfaces()
{
  Lock lock(mutex);
  return local_interfaces_;
}

IfList Options::getRemoteHosts()
{
  Lock lock(mutex);
  return remote_hosts_;
}
