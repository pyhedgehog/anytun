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
#include <string>
#include <sstream>

#include "datatypes.h"
#include "options.h"


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


Options::Options()
{
  progname_ = "anytun";
  sender_id_ = 0;
  local_addr_ = "";
  local_port_ = 4444;
  remote_addr_ = "";
  remote_port_ = 4444;
  dev_name_ = "tap";
  ifconfig_param_local_ = "192.168.200.1";
  ifconfig_param_remote_netmask_ = "255.255.255.0";
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
    PARSE_SCALAR_PARAM("-s","--sender-id", sender_id_)
    PARSE_SCALAR_PARAM("-i","--interface", local_addr_)
    PARSE_SCALAR_PARAM("-p","--port", local_port_)
    PARSE_SCALAR_PARAM("-r","--remote-host", remote_addr_)
    PARSE_SCALAR_PARAM("-o","--remote-port", remote_port_)
    PARSE_SCALAR_PARAM("-d","--dev", dev_name_)
    PARSE_SCALAR_PARAM2("-c","--ifconfig", ifconfig_param_local_, ifconfig_param_remote_netmask_)
    else 
      return false;
  }
  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;
  std::cout << "anytun [-h|--help]                         prints this..." << std::endl;
//  std::cout << "       [-f|--config] <file>                the config file" << std::endl;
  std::cout << "       [-s|--sender-id ] <sender id>       the sender id to use" << std::endl;
  std::cout << "       [-i|--interface] <interface>        local interface to bind to" << std::endl;
  std::cout << "       [-p|--port] <port>                  local port to bind to" << std::endl;
  std::cout << "       [-r|--remote-host] <hostname/ip>    remote host" << std::endl;
  std::cout << "       [-o|--remote-port] <port>           remote port" << std::endl;
  std::cout << "       [-d|--dev] <name>                   device name/type" << std::endl;
  std::cout << "       [-c|--ifconfig] <local>             the local address for the tun/tap device" << std::endl
            << "                       <remote/netmask>    the remote address(tun) or netmask(tap)" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "sender_id='" << sender_id_ << "'" << std::endl;
  std::cout << "local_addr='" << local_addr_ << "'" << std::endl;
  std::cout << "local_port='" << local_port_ << "'" << std::endl;
  std::cout << "remote_addr='" << remote_addr_ << "'" << std::endl;
  std::cout << "remote_port='" << remote_port_ << "'" << std::endl;
  std::cout << "dev_name='" << dev_name_ << "'" << std::endl;
  std::cout << "ifconfig_param_local='" << ifconfig_param_local_ << "'" << std::endl;
  std::cout << "ifconfig_param_remote_netmask='" << ifconfig_param_remote_netmask_ << "'" << std::endl;
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

sender_id_t Options::getSenderId()
{
  return sender_id_;
}

Options& Options::setSenderId(sender_id_t s)
{
  sender_id_ = s;
  return *this;
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

u_int16_t Options::getLocalPort()
{
  return local_port_;
}

Options& Options::setLocalPort(u_int16_t l)
{
  local_port_ = l;
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

std::string Options::getDevName()
{
  Lock lock(mutex);
  return dev_name_;
}

Options& Options::setDevName(std::string d)
{
  Lock lock(mutex);
  dev_name_ = d;
  return *this;
}

std::string Options::getIfconfigParamLocal()
{
  Lock lock(mutex);
  return ifconfig_param_local_;
}

Options& Options::setIfconfigParamLocal(std::string i)
{
  Lock lock(mutex);
  ifconfig_param_local_ = i;
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

