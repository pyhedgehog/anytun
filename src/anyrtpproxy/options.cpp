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

void Host::splitAndSetAddrPort(std::string addr_port)
{
  if(addr_port.length() >= 2 && addr_port[0] == ':' && addr_port[1] != ':') {
    addr_ = "";
    addr_port.erase(0,1);
    std::stringstream tmp_stream(addr_port);    
    tmp_stream >> port_;
    return;
  }

  size_t pos = addr_port.find_first_of("[");

  if(pos != std::string::npos && pos != 0)
    return; // an [ was found but not at the beginning

  bool hasPort = false;
  if(pos != std::string::npos) {
    addr_port.erase(pos, 1);
    pos = addr_port.find_first_of("]");

    if(pos == std::string::npos)
      return; // no trailing ] although an leading [ was found

    if(pos < addr_port.length()-2) {

      if(addr_port[pos+1] != ':')
        return; // wrong port delimieter

      addr_port[pos+1] = '/';
      hasPort = true;
    }
    else if(pos != addr_port.length()-1)
      return; // to few characters left

    addr_port.erase(pos, 1);
  }

  if(hasPort) {
    std::stringstream tmp_stream(addr_port);

    getline(tmp_stream, addr_, '/');
    if(!tmp_stream.good())
      return;

    tmp_stream >> port_;
  }
  else {
    addr_ = addr_port;
    port_ = "2323"; // default sync port
  }
}


Options::Options() : control_interface_("0.0.0.0", "22222")

{
  progname_ = "anyrtpproxy";
  chroot_ = false;
  username_ = "nobody";
  chroot_dir_ = "/var/run";
  daemonize_ = true;
  pid_file_ = "";
  local_addr_ = "";
	local_sync_port_ = "";
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
      /* LIST.clear(); */                                \
			while (tmp.good())                                 \
			{                                                  \
				std::string tmp_line;                            \
				getline(tmp,tmp_line,',');                       \
				LIST.push(tmp_line);                        \
			}                                                  \
      argc--;                                            \
      i++;                                               \
    }

bool Options::parse(int argc, char* argv[])
{
  Lock lock(mutex);

  progname_ = argv[0];
  std::queue<std::string> host_port_queue;
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
    PARSE_SCALAR_PARAM("-P","--write-pid", pid_file_)
    PARSE_SCALAR_PARAM("-i","--interface", local_addr_)
    PARSE_STRING_PARAM("-s","--control", control_interface_)
    PARSE_SCALAR_PARAM2("-p","--port-range", rtp_start_port_, rtp_end_port_)
		PARSE_CSLIST_PARAM("-M","--sync-hosts", host_port_queue)
    PARSE_SCALAR_PARAM("-S","--sync-port", local_sync_port_)
    PARSE_SCALAR_PARAM("-I","--sync-interface", local_sync_addr_)
    else 
      return false;
  }
  while(!host_port_queue.empty())
  {
    std::stringstream tmp_stream(host_port_queue.front());
    OptionConnectTo oct;
    getline(tmp_stream,oct.host,':');
    if(!tmp_stream.good())
      return false;
    tmp_stream >> oct.port;
    host_port_queue.pop();
    connect_to_.push_back(oct);
  }
  
  return sanityCheck();
}

bool Options::sanityCheck()
{
  if(control_interface_.port_ == "") control_interface_.port_ = "22222";
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
  std::cout << "  [-P|--write-pid] <path>          write pid to this file" << std::endl;
  std::cout << "  [-i|--interface] <ip-address>    local ip address to listen to for RTP packets" << std::endl;
  std::cout << "  [-s|--control] <addr>[:<port>]   the address/port to listen on for control commands" << std::endl;
  std::cout << "  [-p|--port-range] <start> <end>  port range used to relay rtp connections" << std::endl;
  std::cout << "  [-n|--nat]                       enable permantent automatic nat detection(use only with anytun)" << std::endl;
  std::cout << "  [-o|--no-nat-once]               disable automatic nat detection for new connections" << std::endl;
  std::cout << "  [-I|--sync-interface] <ip-address>  local unicast(sync) ip address to bind to" << std::endl;
  std::cout << "  [-S|--sync-port] <port>          local unicast(sync) port to bind to" << std::endl;
  std::cout << "  [-M|--sync-hosts] <hostname|ip>:<port>[,<hostname|ip>:<port>[...]]"<< std::endl;
  std::cout << "                                   List of Remote Sync Hosts/Ports"<< std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "chroot='" << chroot_ << "'" << std::endl;
  std::cout << "username='" << username_ << "'" << std::endl;
  std::cout << "chroot-dir='" << chroot_dir_ << "'" << std::endl;
  std::cout << "daemonize='" << daemonize_ << "'" << std::endl;
  std::cout << "pid_file='" << pid_file_ << "'" << std::endl;
  std::cout << "control-interface='" << control_interface_.toString() << "'" << std::endl;
  std::cout << "local_addr='" << local_addr_ << "'" << std::endl;
  std::cout << "rtp_start_port=" << rtp_start_port_ << std::endl;
  std::cout << "rtp_end_port=" << rtp_end_port_ << std::endl;
  std::cout << "local_sync_addr='" << local_sync_addr_ << "'" << std::endl;
  std::cout << "local_sync_port='" << local_sync_port_ << "'" << std::endl;
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

std::string Options::getPidFile()
{
  Lock lock(mutex);
  return pid_file_;
}

Host Options::getControlInterface()
{
  Lock lock(mutex);
  return control_interface_;
}

std::string Options::getLocalAddr()
{
  Lock lock(mutex);
  return local_addr_;
}

Options& Options::setLocalAddr(std::string l)
{
  Lock lock(mutex);
  local_addr_ = l;
  return *this;
}

std::string Options::getLocalSyncAddr()
{
  Lock lock(mutex);
  return local_sync_addr_;
}

Options& Options::setLocalSyncAddr(std::string l)
{
  Lock lock(mutex);
  local_sync_addr_ = l;
  return *this;
}

std::string Options::getLocalSyncPort()
{
  Lock lock(mutex);
  return local_sync_port_;
}

Options& Options::setLocalSyncPort(std::string l)
{
  Lock lock(mutex);
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

