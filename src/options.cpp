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

#include <cstring>
#include <iostream>
#include <queue>
#include <string>
#include <sstream>

#include "datatypes.h"
#include "options.h"
#include "log.h"

std::ostream& operator<<(std::ostream& stream, syntax_error const& error)
{
  stream << "syntax error: " << error.what() << std::endl;
  stream << "              ";
  for(u_int32_t i = 0; i < error.pos; ++i) stream << " ";
  return stream << "^";
}

void OptionHost::init(std::string addrPort)
{
  std::string origAddrPort(addrPort);
  size_t pos = addrPort.find_first_of("[");

  if(pos != std::string::npos && pos != 0)
    throw syntax_error(origAddrPort, pos); // an [ was found but not at the beginning;

  bool hasPort = false;
  if(pos != std::string::npos) {
    addrPort.erase(pos, 1);
    pos = addrPort.find_first_of("]");

    if(pos == std::string::npos)
      throw syntax_error(origAddrPort, origAddrPort.length()); //no trailing ] although an leading [ was found

    if(pos < addrPort.length()-2) {
      if(addrPort[pos+1] != ':')
        throw syntax_error(origAddrPort, pos+2); // wrong port delimieter

      addrPort[pos+1] = '/';
      hasPort = true;
    }
    else if(pos != addrPort.length()-1)
      throw syntax_error(origAddrPort, pos+2); // too few characters left

    addrPort.erase(pos, 1);
  }
  else {
    pos = addrPort.find_first_of(":");
    if(pos != std::string::npos && pos == addrPort.find_last_of(":")) {
      // an ':' has been found and it is the only one -> assuming port present
      hasPort = true;
      addrPort[pos] = '/';
    }
  }

  if(hasPort) {
    std::stringstream tmp_stream(addrPort);

    getline(tmp_stream, addr, '/');
    if(!tmp_stream.good())
      throw syntax_error(origAddrPort, addr.length());

    tmp_stream >> port;
  }
  else {
    addr = addrPort;
    port = "2323"; // default sync port
  }
}

std::istream& operator>>(std::istream& stream, OptionHost& host)
{
  std::string tmp;
  stream >> tmp;
  host.init(tmp);
  return stream;
}

void OptionRoute::init(std::string route) 
{
  std::stringstream tmp_stream(route);
  getline(tmp_stream, net_addr, '/');
  if(!tmp_stream.good())
    throw syntax_error(route, net_addr.length());
  tmp_stream >> prefix_length;
}

std::istream& operator>>(std::istream& stream, OptionRoute& route)
{
  std::string tmp;
  stream >> tmp;
  route.init(tmp);
  return stream;
}

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
  chroot_ = false;
  username_ = "nobody";
  chroot_dir_ = "/var/run/anytun";
  pid_file_ = "";

  file_name_ = "";
  bind_to_.addr = "127.0.0.1";
  bind_to_.port = "2323";

  local_addr_ = "";
  local_port_ = "4444";
  remote_addr_ = "";
  remote_port_ = "4444";
  local_sync_addr_ = "";
  local_sync_port_ = "";

  dev_name_ = "";
  dev_type_ = "";
  ifconfig_param_local_ = "";
  ifconfig_param_remote_netmask_ = "";
  post_up_script_ = "";

  sender_id_ = 0;
  mux_ = 0;
  seq_window_size_ = 0;

  cipher_ = "aes-ctr";
  auth_algo_ = "sha1";
  kd_prf_ = "aes-ctr";
  ld_kdr_ = 0;
}

Options::~Options()
{
}

#define PARSE_BOOL_PARAM(SHORT, LONG, VALUE)                                    \
    else if(str == SHORT || str == LONG)                                        \
      VALUE = true;

#define PARSE_INVERSE_BOOL_PARAM(SHORT, LONG, VALUE)                            \
    else if(str == SHORT || str == LONG)                                        \
      VALUE = false;

#define PARSE_SIGNED_INT_PARAM(SHORT, LONG, VALUE)                              \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1];                                                         \
      tmp >> VALUE;                                                             \
      argc--;                                                                   \
      i++;                                                                      \
    }

#define PARSE_SCALAR_PARAM(SHORT, LONG, VALUE)                                  \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        u_int32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1];                                                         \
      tmp >> VALUE;                                                             \
      argc--;                                                                   \
      i++;                                                                      \
    }

#define PARSE_SCALAR_PARAM2(SHORT, LONG, VALUE1, VALUE2)                        \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argc < 2)                                                              \
        throw syntax_error(str.append(" ").append(argv[i+1]), str.length());    \
      if(argv[i+1][0] == '-') {                                                 \
        u_int32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      if(argv[i+2][0] == '-') {                                                 \
        u_int32_t pos = str.length() + 1 + strlen(argv[i+1]) + 1;               \
        throw syntax_error(str.append(" ").append(argv[i+1]).append(" ").append(argv[i+2]), pos); \
      }                                                                         \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1] << " " << argv[i+2];                                     \
      tmp >> VALUE1;                                                            \
      tmp >> VALUE2;                                                            \
      argc-=2;                                                                  \
      i+=2;                                                                     \
    }

#define PARSE_HEXSTRING_PARAM_SEC(SHORT, LONG, VALUE)                           \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        u_int32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      VALUE = Buffer(std::string(argv[i+1]));                                   \
      for(size_t j=0; j < strlen(argv[i+1]); ++j)                               \
        argv[i+1][j] = '#';                                                     \
      argc--;                                                                   \
      i++;                                                                      \
    }

#define PARSE_CSLIST_PARAM(SHORT, LONG, LIST)                                   \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        u_int32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      std::stringstream tmp(argv[i+1]);                                         \
			while (tmp.good())                                                        \
			{                                                                         \
				std::string tmp_line;                                                   \
				getline(tmp,tmp_line,',');                                              \
				LIST.push(tmp_line);                                                    \
			}                                                                         \
      argc--;                                                                   \
      i++;                                                                      \
    }

bool Options::parse(int argc, char* argv[])
{
  Lock lock(mutex);

  progname_ = argv[0];
  argc--;
  std::queue<std::string> host_port_queue;
  int32_t ld_kdr_tmp = ld_kdr_;
  std::queue<std::string> route_queue;
  for(int i=1; argc > 0; ++i)
  {
    std::string str(argv[i]);
    argc--;

    if(str == "-h" || str == "--help")
      return false;
    PARSE_INVERSE_BOOL_PARAM("-D","--nodaemonize", daemonize_)
    PARSE_BOOL_PARAM("-C","--chroot", chroot_)
    PARSE_SCALAR_PARAM("-u","--username", username_)
    PARSE_SCALAR_PARAM("-H","--chroot-dir", chroot_dir_)
    PARSE_SCALAR_PARAM("-P","--write-pid", pid_file_)

//     PARSE_SCALAR_PARAM("-f","--file", file_name_)
//     PARSE_SCALAR_PARAM("-X","--control-host", bind_to_)

    PARSE_SCALAR_PARAM("-i","--interface", local_addr_)
    PARSE_SCALAR_PARAM("-p","--port", local_port_)
    PARSE_SCALAR_PARAM("-r","--remote-host", remote_addr_)
    PARSE_SCALAR_PARAM("-o","--remote-port", remote_port_)
    PARSE_SCALAR_PARAM("-I","--sync-interface", local_sync_addr_)
    PARSE_SCALAR_PARAM("-S","--sync-port", local_sync_port_)
    PARSE_CSLIST_PARAM("-M","--sync-hosts", host_port_queue)
    PARSE_CSLIST_PARAM("-X","--control-host", host_port_queue)

    PARSE_SCALAR_PARAM("-d","--dev", dev_name_)
    PARSE_SCALAR_PARAM("-t","--type", dev_type_)
    PARSE_SCALAR_PARAM2("-n","--ifconfig", ifconfig_param_local_, ifconfig_param_remote_netmask_)
    PARSE_SCALAR_PARAM("-x","--post-up-script", post_up_script_)
    PARSE_CSLIST_PARAM("-R","--route", route_queue)

    PARSE_SCALAR_PARAM("-s","--sender-id", sender_id_)
    PARSE_SCALAR_PARAM("-m","--mux", mux_)
    PARSE_SCALAR_PARAM("-w","--window-size", seq_window_size_)

    PARSE_SCALAR_PARAM("-c","--cipher", cipher_)
    PARSE_SCALAR_PARAM("-a","--auth-algo", auth_algo_)
    PARSE_SCALAR_PARAM("-k","--kd-prf", kd_prf_)
    PARSE_SIGNED_INT_PARAM("-l","--ld-kdr", ld_kdr_tmp)
    PARSE_HEXSTRING_PARAM_SEC("-K","--key", key_)
    PARSE_HEXSTRING_PARAM_SEC("-A","--salt", salt_)
    else 
      throw syntax_error(str, 0);
  }

  ld_kdr_ = static_cast<int8_t>(ld_kdr_tmp);

  if(cipher_ == "null" && auth_algo_ == "null")
    kd_prf_ = "null";
  if((cipher_ != "null" || auth_algo_ != "null") && kd_prf_ == "null")
    cLog.msg(Log::PRIO_WARNING) << "using NULL key derivation with encryption and or authentication enabled!";

  if(dev_name_ == "" && dev_type_ == "")
    dev_type_ = "tun";

	while(!host_port_queue.empty()) {
    OptionHost sh(host_port_queue.front());
    remote_sync_hosts_.push_back(sh);
    host_port_queue.pop();
	}

	while(!route_queue.empty()) {
    OptionRoute rt(route_queue.front());
    routes_.push_back(rt);
    route_queue.pop();
  }

  return true;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;
  std::cout << "anytun " << std::endl;
  std::cout << "   [-h|--help]                         prints this..." << std::endl;

  std::cout << "   [-D|--nodaemonize]                  don't run in background" << std::endl;
  std::cout << "   [-C|--chroot]                       chroot and drop privileges" << std::endl;
  std::cout << "   [-u|--username] <username>          if chroot change to this user" << std::endl;
  std::cout << "   [-H|--chroot-dir] <path>            chroot to this directory" << std::endl;
  std::cout << "   [-P|--write-pid] <path>             write pid to this file" << std::endl;

//   std::cout << "   [-f|--file] <path>                  path to input file" << std::endl;
//   std::cout << "   [-X|--control-host] < <hostname|ip>[:<port>] | :<port> >" << std::endl;
//   std::cout << "                                      local tcp port and or ip address to bind to" << std::endl;

  std::cout << "   [-i|--interface] <hostname|ip>      local anycast ip address to bind to" << std::endl;
  std::cout << "   [-p|--port] <port>                  local anycast(data) port to bind to" << std::endl;
  std::cout << "   [-r|--remote-host] <hostname|ip>    remote host" << std::endl;
  std::cout << "   [-o|--remote-port] <port>           remote port" << std::endl;
  std::cout << "   [-I|--sync-interface] <ip-address>  local unicast(sync) ip address to bind to" << std::endl;
  std::cout << "   [-S|--sync-port] <port>             local unicast(sync) port to bind to" << std::endl;
  std::cout << "   [-M|--sync-hosts] <hostname|ip>[:<port>][,<hostname|ip>[:<port>][...]]"<< std::endl;
	std::cout << "                                       remote hosts to sync with" << std::endl;
  std::cout << "   [-X|--control-host] <hostname|ip>[:<port>]"<< std::endl;
	std::cout << "                                       fetch the config from this host" << std::endl;

  std::cout << "   [-d|--dev] <name>                   device name" << std::endl;
  std::cout << "   [-t|--type] <tun|tap>               device type" << std::endl;
  std::cout << "   [-n|--ifconfig] <local>             the local address for the tun/tap device" << std::endl
            << "                   <remote|netmask>    the remote address(tun) or netmask(tap)" << std::endl;
  std::cout << "   [-x|--post-up-script] <script>      script gets called after interface is created" << std::endl;
  std::cout << "   [-R|--route] <net>/<prefix length>  add a route to connection, can be invoked several times" << std::endl;

  std::cout << "   [-s|--sender-id ] <sender id>       the sender id to use" << std::endl;
  std::cout << "   [-m|--mux] <mux-id>                 the multiplex id to use" << std::endl;
  std::cout << "   [-w|--window-size] <window size>    seqence number window size" << std::endl;

  std::cout << "   [-c|--cipher] <cipher type>         payload encryption algorithm" << std::endl;
  std::cout << "   [-a|--auth-algo] <algo type>        message authentication algorithm" << std::endl;
  std::cout << "   [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function" << std::endl;
  std::cout << "   [-l|--ld-kdr] <ld-kdr>              log2 of key derivation rate" << std::endl;
  std::cout << "   [-K|--key] <master key>             master key to use for encryption" << std::endl;
  std::cout << "   [-A|--salt] <master salt>           master salt to use for encryption" << std::endl;
}

void Options::printOptions()
{
  Lock lock(mutex);
  std::cout << "Options:" << std::endl;
  std::cout << std::endl;
  std::cout << "daemonize=" << daemonize_ << std::endl;
  std::cout << "chroot=" << chroot_ << std::endl;
  std::cout << "username='" << username_ << "'" << std::endl;
  std::cout << "chroot_dir='" << chroot_dir_ << "'" << std::endl;
  std::cout << "pid_file='" << pid_file_ << "'" << std::endl;
  std::cout << std::endl;
//   std::cout << "file_name='" << file_name_ << "'" << std::endl;
//   std::cout << "bind_to.addr='" << bind_to_.addr << "'" << std::endl;
//   std::cout << "bind_to.port='" << bind_to_.port << "'" << std::endl;
//   std::cout << std::endl;
  std::cout << "local_addr='" << local_addr_ << "'" << std::endl;
  std::cout << "local_port='" << local_port_ << "'" << std::endl;
  std::cout << "remote_addr='" << remote_addr_ << "'" << std::endl;
  std::cout << "remote_port='" << remote_port_ << "'" << std::endl;
  std::cout << "local_sync_addr='" << local_sync_addr_ << "'" << std::endl;
  std::cout << "local_sync_port='" << local_sync_port_ << "'" << std::endl;
  std::cout << "remote_sync_hosts=";
  HostList::const_iterator it = remote_sync_hosts_.begin();
  for(; it != remote_sync_hosts_.end(); ++it)
    std::cout << "'" << it->addr << "','" << it->port << "'; ";
  std::cout << std::endl;
  std::cout << std::endl;
  std::cout << "dev_name='" << dev_name_ << "'" << std::endl;
  std::cout << "dev_type='" << dev_type_ << "'" << std::endl;
  std::cout << "ifconfig_param_local='" << ifconfig_param_local_ << "'" << std::endl;
  std::cout << "ifconfig_param_remote_netmask='" << ifconfig_param_remote_netmask_ << "'" << std::endl;
  std::cout << "post_up_script='" << post_up_script_ << "'" << std::endl;
  std::cout << "routes:" << std::endl;
  RouteList::const_iterator rit;
  for(rit = routes_.begin(); rit != routes_.end(); ++rit)
    std::cout << "  " << rit->net_addr << "/" << rit->prefix_length << std::endl;
  std::cout << std::endl;
  std::cout << "sender_id='" << sender_id_ << "'" << std::endl;
  std::cout << "mux_id=" << mux_ << std::endl;
  std::cout << "seq_window_size='" << seq_window_size_ << "'" << std::endl;
  std::cout << std::endl;
  std::cout << "cipher='" << cipher_ << "'" << std::endl;
  std::cout << "auth_algo='" << auth_algo_ << "'" << std::endl;
  std::cout << "kd_prf='" << kd_prf_ << "'" << std::endl;
  std::cout << "ld_kdr=" << static_cast<int32_t>(ld_kdr_) << std::endl;
  std::cout << "key=" << key_.getHexDumpOneLine() << std::endl;
  std::cout << "salt=" << salt_.getHexDumpOneLine() << std::endl;
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
  return bind_to_.addr;
}

Options& Options::setBindToAddr(std::string b)
{
  Lock lock(mutex);
  bind_to_.addr = b;
  return *this;
}

std::string Options::getBindToPort()
{
  return bind_to_.port;  
}

Options& Options::setBindToPort(std::string b)
{
  bind_to_.port = b;
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

std::string Options::getLocalPort()
{
  return local_port_;
}

Options& Options::setLocalPort(std::string l)
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

std::string Options::getRemotePort()
{
  return remote_port_;
}

Options& Options::setRemotePort(std::string r)
{
  remote_port_ = r;
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
  return local_sync_port_;
}

Options& Options::setLocalSyncPort(std::string l)
{
  local_sync_port_ = l;
  return *this;
}

HostList Options::getRemoteSyncHosts()
{
  Lock lock(mutex);
	return remote_sync_hosts_;
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

std::string Options::getPostUpScript()
{
  Lock lock(mutex);
  return post_up_script_;
}

Options& Options::setPostUpScript(std::string p)
{
  Lock lock(mutex);
  post_up_script_ = p;
  return *this;
}

RouteList Options::getRoutes()
{
  Lock lock(mutex);
  return routes_;
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

mux_t Options::getMux()
{
  Lock lock(mutex);
  return mux_;
}

Options& Options::setMux(mux_t m)
{
  Lock lock(mutex);
  mux_ = m;
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

int8_t Options::getLdKdr()
{
  Lock lock(mutex);
  return ld_kdr_;
}

Options& Options::setLdKdr(int8_t l)
{
  Lock lock(mutex);
  ld_kdr_ = l;
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
