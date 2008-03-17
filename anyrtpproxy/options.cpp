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

Options::Options() : control_interface_("0.0.0.0", 22222)

{
  progname_ = "anyrtpproxy";
  chroot_ = false;
  username_ = "nobody";
  chroot_dir_ = "/var/run";
  daemonize_ = true;
	local_sync_port_ = 2023;
	rtp_start_port_ = 34000;
	rtp_end_port_ = 35000;
	no_nat_once_ = false;
	nat_ = false;
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

#define PARSE_STRING_PARAM(SHORT, LONG, VALUE)           \
    else if(str == SHORT || str == LONG)                 \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return false;                                    \
      VALUE = std::string(argv[i+1]);                    \
      argc--;                                            \
      i++;                                               \
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
    PARSE_BOOL_PARAM("-n","--nat", nat_)
    PARSE_BOOL_PARAM("-o","--no-nat-once", no_nat_once_)
    PARSE_SCALAR_PARAM("-u","--user", username_)
    PARSE_SCALAR_PARAM("-c","--chroot-dir", chroot_dir_)
    PARSE_INVERSE_BOOL_PARAM("-d","--nodaemonize", daemonize_)
    PARSE_STRING_PARAM("-s","--control", control_interface_)
    PARSE_SCALAR_PARAM2("-p","--port-range", rtp_start_port_, rtp_end_port_)
    else 
      return false;
  }
  
  return sanityCheck();
}

bool Options::sanityCheck()
{
  if(!control_interface_.port_) control_interface_.port_ = 22220;
  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE: anyrtpproxy" << std::endl;
  std::cout << "  [-h|--help]                      prints this..." << std::endl;
  std::cout << "  [-t|--chroot]                    chroot and drop priviledges" << std::endl;
  std::cout << "  [-u|--username] <username>       in case of chroot run as this user" << std::endl;
  std::cout << "  [-c|--chroot-dir] <directory>    directory to make a chroot to" << std::endl;
  std::cout << "  [-d|--nodaemonize]               don't run in background" << std::endl;
  std::cout << "  [-s|--control] <addr[:port]>     the address/port to listen on for control commands" << std::endl;
  std::cout << "  [-p|--port-range] <start> <end>  port range used to relay rtp connections" << std::endl;
  std::cout << "  [-n|--nat]                       enable permantent automatic nat detection(use only with anytun)" << std::endl;
  std::cout << "  [-o|--no-nat-once]               disable automatic nat detection for new connections" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "chroot='" << chroot_ << "'" << std::endl;
  std::cout << "username='" << username_ << "'" << std::endl;
  std::cout << "chroot-dir='" << chroot_dir_ << "'" << std::endl;
  std::cout << "daemonize='" << daemonize_ << "'" << std::endl;
  std::cout << "control-interface='" << control_interface_.toString() << "'" << std::endl;
}

std::string Options::getProgname()
{
  Lock lock(mutex);
  return progname_;
}

bool Options::getChroot()
{
  Lock lock(mutex);
  return chroot_;
}

bool Options::getNat()
{
  Lock lock(mutex);
  return nat_;
}

bool Options::getNoNatOnce()
{
  Lock lock(mutex);
  return no_nat_once_;
}

std::string Options::getUsername()
{
  Lock lock(mutex);
  return username_;
}

std::string Options::getChrootDir()
{
  Lock lock(mutex);
  return chroot_dir_;
}

bool Options::getDaemonize()
{
  Lock lock(mutex);
  return daemonize_;
}

Host Options::getControlInterface()
{
  Lock lock(mutex);
  return control_interface_;
}

u_int16_t Options::getLocalSyncPort()
{
  return local_sync_port_;
}

Options& Options::setLocalSyncPort(u_int16_t l)
{
  local_sync_port_ = l;
  return *this;
}

u_int16_t Options::getRtpStartPort()
{
  return rtp_start_port_;
}

Options& Options::setRtpStartPort(u_int16_t l)
{
  rtp_start_port_ = l;
  return *this;
}

u_int16_t Options::getRtpEndPort()
{
  return rtp_end_port_;
}

Options& Options::setRtpEndPort(u_int16_t l)
{
  rtp_end_port_ = l;
  return *this;
}

ConnectToList Options::getConnectTo()
{
  Lock lock(mutex);
  return connect_to_;
}

