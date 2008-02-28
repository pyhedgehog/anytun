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

#include "datatypes.h"
#include "anyctrOptions.h"

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

Options::Options() : key_(u_int32_t(0)), salt_(u_int32_t(0))
{
  progname_ = "anyctr";
  remote_addr_ = "";
  remote_port_ = 4444;
  ifconfig_param_remote_netmask_ = "255.255.255.0";
  seq_window_size_ = 100;
  kd_prf_ = "aes-ctr";
  mux_ = 0;
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
  std::queue<std::string> host_port_queue;
  for(int i=1; argc > 0; ++i)
  {
    std::string str(argv[i]);
    argc--;

    if(str == "-h" || str == "--help")
      return false;
    PARSE_SCALAR_PARAM("-r","--remote-host", remote_addr_)
    PARSE_SCALAR_PARAM("-o","--remote-port", remote_port_)
    PARSE_SCALAR_PARAM2("-n","--ifconfig", ifconfig_param_local_, ifconfig_param_remote_netmask_)
    PARSE_SCALAR_PARAM("-w","--window-size", seq_window_size_)
    PARSE_SCALAR_PARAM("-m","--mux", mux_)
    PARSE_HEXSTRING_PARAM("-K","--key", key_)
    PARSE_HEXSTRING_PARAM("-a","--salt", salt_)
    PARSE_SCALAR_PARAM("-k","--kd-prf", kd_prf_)
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
  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;
  std::cout << "anyctr [-h|--help]                         prints this..." << std::endl;
  std::cout << "       [-r|--remote-host] <hostname|ip>    remote host" << std::endl;
  std::cout << "       [-o|--remote-port] <port>           remote port" << std::endl;
  std::cout << "       [-n|--ifconfig] <local>             the local address for the tun/tap device" << std::endl
            << "                       <remote|netmask>    the remote address(tun) or netmask(tap)" << std::endl;
  std::cout << "       [-w|--window-size] <window size>    seqence number window size" << std::endl;
  std::cout << "       [-m|--mux] <mux-id>                 the multiplex id to use" << std::endl;
  std::cout << "       [-K|--key] <master key>             master key to use for encryption" << std::endl;
  std::cout << "       [-a|--salt] <master salt>           master salt to use for encryption" << std::endl;
  std::cout << "       [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "remote_addr='" << remote_addr_ << "'" << std::endl;
  std::cout << "remote_port='" << remote_port_ << "'" << std::endl;
  std::cout << "ifconfig_param_local='" << ifconfig_param_local_ << "'" << std::endl;
  std::cout << "ifconfig_param_remote_netmask='" << ifconfig_param_remote_netmask_ << "'" << std::endl;
  std::cout << "seq_window_size='" << seq_window_size_ << "'" << std::endl;
  std::cout << "mux_id='" << mux_ << "'" << std::endl;
  std::cout << "key=" << key_.getHexDumpOneLine() << std::endl;
  std::cout << "salt=" << salt_.getHexDumpOneLine() << std::endl;
  std::cout << "kd_prf='" << kd_prf_ << "'" << std::endl;
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


std::string Options::getRemoteAddr()
{
  Lock lock(mutex);
  return remote_addr_;
}

Options& Options::setRemoteAddr(std::string r)
{
  Lock lock(mutex);
  remote_addr_ = r;
  return *this;
}

u_int16_t Options::getRemotePort()
{
  return remote_port_;
}

Options& Options::setRemotePort(u_int16_t r)
{
  remote_port_ = r;
  return *this;
}

Options& Options::setRemoteAddrPort(std::string addr, u_int16_t port)
{
  Lock lock(mutex);
  remote_addr_ = addr;
  remote_port_ = port;
  return *this;
}

std::string Options::getIfconfigParamRemoteNetmask()
{
  Lock lock(mutex);
  return ifconfig_param_remote_netmask_;
}

Options& Options::setIfconfigParamRemoteNetmask(std::string i)
{
  Lock lock(mutex);
  ifconfig_param_remote_netmask_ = i;
  return *this;
}

window_size_t Options::getSeqWindowSize()
{
  return seq_window_size_;
}

Options& Options::setSeqWindowSize(window_size_t s)
{
  seq_window_size_ = s;
  return *this;
}


std::string Options::getKdPrf()
{
  Lock lock(mutex);
  return kd_prf_;
}

Options& Options::setKdPrf(std::string k)
{
  Lock lock(mutex);
  kd_prf_ = k;
  return *this;
}

u_int16_t Options::getMux()
{
  Lock lock(mutex);
  return mux_;
}

Options& Options::setMux(u_int16_t m)
{
  Lock lock(mutex);
  mux_ = m;
  return *this;
}

Buffer Options::getKey()
{
  Lock lock(mutex);
  return key_;
}

Options& Options::setKey(std::string k)
{
  Lock lock(mutex);
  key_ = k;
  return *this;
}

Buffer Options::getSalt()
{
  Lock lock(mutex);
  return salt_;
}

Options& Options::setSalt(std::string s)
{
  Lock lock(mutex);
  salt_ = s;
  return *this;
}
