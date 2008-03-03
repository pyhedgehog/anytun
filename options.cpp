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

Options::Options() : key_(u_int32_t(0)), salt_(u_int32_t(0))
{
  progname_ = "anytun";
  daemonize_ = true;
  sender_id_ = 0;
  local_addr_ = "";
  local_port_ = 4444;
  local_sync_port_ = 0;
  remote_sync_port_ = 0;
  remote_sync_addr_ = "";
  remote_addr_ = "";
  remote_port_ = 4444;
  dev_name_ = "tap";
  dev_type_ = "";
  ifconfig_param_local_ = "192.168.200.1";
  ifconfig_param_remote_netmask_ = "255.255.255.0";
  seq_window_size_ = 100;
  cipher_ = "aes-ctr";
  kd_prf_ = "aes-ctr";
  auth_algo_ = "sha1";
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
    PARSE_INVERSE_BOOL_PARAM("-D","--nodaemonize", daemonize_)
    PARSE_SCALAR_PARAM("-s","--sender-id", sender_id_)
    PARSE_SCALAR_PARAM("-i","--interface", local_addr_)
    PARSE_SCALAR_PARAM("-p","--port", local_port_)
    PARSE_SCALAR_PARAM("-S","--sync-port", local_sync_port_)
    PARSE_SCALAR_PARAM("-I","--sync-interface", local_sync_addr_)
    PARSE_SCALAR_PARAM("-R","--remote-sync-host", remote_sync_addr_)
    PARSE_SCALAR_PARAM("-O","--remote-sync-port", remote_sync_port_)
    PARSE_SCALAR_PARAM("-r","--remote-host", remote_addr_)
    PARSE_SCALAR_PARAM("-o","--remote-port", remote_port_)
    PARSE_SCALAR_PARAM("-d","--dev", dev_name_)
    PARSE_SCALAR_PARAM("-t","--type", dev_type_)
    PARSE_SCALAR_PARAM2("-n","--ifconfig", ifconfig_param_local_, ifconfig_param_remote_netmask_)
    PARSE_SCALAR_PARAM("-w","--window-size", seq_window_size_)
    PARSE_SCALAR_PARAM("-m","--mux", mux_)
    PARSE_SCALAR_PARAM("-c","--cipher", cipher_)
    PARSE_HEXSTRING_PARAM("-K","--key", key_)
    PARSE_HEXSTRING_PARAM("-A","--salt", salt_)
    PARSE_SCALAR_PARAM("-k","--kd-prf", kd_prf_)
    PARSE_SCALAR_PARAM("-a","--auth-algo", auth_algo_)
		PARSE_CSLIST_PARAM("-M","--sync-hosts", host_port_queue)
    else 
      return false;
  }

  if(cipher_ == "null" && auth_algo_ == "null")
    kd_prf_ = "null";
  if((cipher_ != "null" || auth_algo_ != "null") && kd_prf_ == "null")
    kd_prf_ = "aes-ctr";

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
  std::cout << "anytun [-h|--help]                         prints this..." << std::endl;
//  std::cout << "       [-f|--config] <file>                the config file" << std::endl;
  std::cout << "       [-D|--nodaemonize]                  don't run in background" << std::endl;
  std::cout << "       [-s|--sender-id ] <sender id>       the sender id to use" << std::endl;
  std::cout << "       [-i|--interface] <ip-address>       local anycast ip address to bind to" << std::endl;
  std::cout << "       [-p|--port] <port>                  local anycast(data) port to bind to" << std::endl;
  std::cout << "       [-I|--sync-interface] <ip-address>  local unicast(sync) ip address to bind to" << std::endl;
  std::cout << "       [-S|--sync-port] <port>             local unicast(sync) port to bind to" << std::endl;
  std::cout << "       [-M|--sync-hosts] <hostname|ip>:<port>[,<hostname|ip>:<port>[...]]"<< std::endl;
	std::cout << "                                           remote hosts to sync with" << std::endl;
  std::cout << "       [-r|--remote-host] <hostname|ip>    remote host" << std::endl;
  std::cout << "       [-o|--remote-port] <port>           remote port" << std::endl;
  std::cout << "       [-d|--dev] <name>                   device name" << std::endl;
  std::cout << "       [-t|--type] <tun|tap>               device type" << std::endl;
  std::cout << "       [-n|--ifconfig] <local>             the local address for the tun/tap device" << std::endl
            << "                       <remote|netmask>    the remote address(tun) or netmask(tap)" << std::endl;
  std::cout << "       [-w|--window-size] <window size>    seqence number window size" << std::endl;
  std::cout << "       [-m|--mux] <mux-id>                 the multiplex id to use" << std::endl;
  std::cout << "       [-c|--cipher] <cipher type>         payload encryption algorithm" << std::endl;
  std::cout << "       [-K|--key] <master key>             master key to use for encryption" << std::endl;
  std::cout << "       [-A|--salt] <master salt>           master salt to use for encryption" << std::endl;
  std::cout << "       [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function" << std::endl;
  std::cout << "       [-a|--auth-algo] <algo type>        message authentication algorithm" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << "daemonize=" << daemonize_ << std::endl;
  std::cout << "sender_id='" << sender_id_ << "'" << std::endl;
  std::cout << "local_addr='" << local_addr_ << "'" << std::endl;
  std::cout << "local_port='" << local_port_ << "'" << std::endl;
  std::cout << "local_sync_addr='" << local_sync_addr_ << "'" << std::endl;
  std::cout << "local_sync_port='" << local_sync_port_ << "'" << std::endl;
  std::cout << "remote_addr='" << remote_addr_ << "'" << std::endl;
  std::cout << "remote_port='" << remote_port_ << "'" << std::endl;
  std::cout << "dev_name='" << dev_name_ << "'" << std::endl;
  std::cout << "dev_type='" << dev_type_ << "'" << std::endl;
  std::cout << "ifconfig_param_local='" << ifconfig_param_local_ << "'" << std::endl;
  std::cout << "ifconfig_param_remote_netmask='" << ifconfig_param_remote_netmask_ << "'" << std::endl;
  std::cout << "seq_window_size='" << seq_window_size_ << "'" << std::endl;
  std::cout << "mux_id='" << mux_ << "'" << std::endl;
  std::cout << "cipher='" << cipher_ << "'" << std::endl;
  std::cout << "key=" << key_.getHexDumpOneLine() << std::endl;
  std::cout << "salt=" << salt_.getHexDumpOneLine() << std::endl;
  std::cout << "kd_prf='" << kd_prf_ << "'" << std::endl;
  std::cout << "auth_algo='" << auth_algo_ << "'" << std::endl;
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

ConnectToList Options::getConnectTo()
{
  Lock lock(mutex);
	return connect_to_;
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

u_int16_t Options::getLocalPort()
{
  return local_port_;
}

Options& Options::setLocalPort(u_int16_t l)
{
  local_port_ = l;
  return *this;
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

u_int16_t Options::getRemoteSyncPort()
{
  return remote_sync_port_;
}

Options& Options::setRemoteSyncPort(u_int16_t l)
{
  remote_sync_port_ = l;
  return *this;
}

std::string Options::getRemoteSyncAddr()
{
  Lock lock(mutex);
  return remote_sync_addr_;
}

Options& Options::setRemoteSyncAddr(std::string r)
{
  Lock lock(mutex);
  remote_sync_addr_ = r;
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

std::string Options::getDevType()
{
  Lock lock(mutex);
  return dev_type_;
}

Options& Options::setDevName(std::string d)
{
  Lock lock(mutex);
  dev_name_ = d;
  return *this;
}

Options& Options::setDevType(std::string d)
{
  Lock lock(mutex);
  dev_type_ = d;
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

window_size_t Options::getSeqWindowSize()
{
  return seq_window_size_;
}

Options& Options::setSeqWindowSize(window_size_t s)
{
  seq_window_size_ = s;
  return *this;
}

std::string Options::getCipher()
{
  Lock lock(mutex);
  return cipher_;
}

Options& Options::setCipher(std::string c)
{
  Lock lock(mutex);
  cipher_ = c;
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

std::string Options::getAuthAlgo()
{
  Lock lock(mutex);
  return auth_algo_;
}

Options& Options::setAuthAlgo(std::string a)
{
  Lock lock(mutex);
  auth_algo_ = a;
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
