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

#include <cstring>
#include <iostream>
#include <queue>
#include <string>
#include <sstream>

#include "datatypes.h"
#include "version.h"

#include "options.h"
#include "log.h"
#include "authAlgoFactory.h"

std::ostream& operator<<(std::ostream& stream, syntax_error const& error)
{
  stream << "syntax error: " << error.what() << std::endl;
  if(error.pos >= 0) {
    stream << "              ";
    for(int32_t i = 0; i < error.pos; ++i) { stream << " "; }
    return stream << "^";
  }
  return stream;
}

std::ostream& operator<<(std::ostream& stream, role_t const& role)
{
  switch(role) {
  case ROLE_LEFT:
    stream << "left";
    break;
  case ROLE_RIGHT:
    stream << "right";
    break;
  default:
    stream << "unknown";
    break;
  }
  return stream;
}

void OptionHost::init(std::string addrPort)
{
  std::string origAddrPort(addrPort);
  size_t pos = addrPort.find_first_of("[");

  if(pos != std::string::npos && pos != 0) {
    throw syntax_error(origAddrPort, pos);  // an [ was found but not at the beginning;
  }

  bool hasPort = false;
  if(pos != std::string::npos) {
    addrPort.erase(pos, 1);
    pos = addrPort.find_first_of("]");

    if(pos == std::string::npos) {
      throw syntax_error(origAddrPort, origAddrPort.length());  //no trailing ] although an leading [ was found
    }

    if(pos < addrPort.length()-2) {
      if(addrPort[pos+1] != ':') {
        throw syntax_error(origAddrPort, pos+2);  // wrong port delimieter
      }

      addrPort[pos+1] = '/';
      hasPort = true;
    } else if(pos != addrPort.length()-1) {
      throw syntax_error(origAddrPort, pos+2);  // too few characters left
    }

    addrPort.erase(pos, 1);
  } else {
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
    if(!tmp_stream.good()) {
      throw syntax_error(origAddrPort, addr.length());
    }

    tmp_stream >> port;
  } else {
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

void OptionNetwork::init(std::string network)
{
  std::stringstream tmp_stream(network);
  getline(tmp_stream, net_addr, '/');
  if(!tmp_stream.good()) {
    throw syntax_error(network, net_addr.length());
  }
  tmp_stream >> prefix_length;
}

std::istream& operator>>(std::istream& stream, OptionNetwork& network)
{
  std::string tmp;
  stream >> tmp;
  network.init(tmp);
  return stream;
}

Options* Options::inst = NULL;
Mutex Options::instMutex;
Options& gOpt = Options::instance();

Options& Options::instance()
{
  Lock lock(instMutex);
  static instanceCleaner c;
  if(!inst) {
    inst = new Options();
  }

  return *inst;
}

Options::Options() : key_(uint32_t(0)), salt_(uint32_t(0))
{
#if defined(ANYCTR_OPTIONS)
  progname_ = "anytun-controld";
#elif defined(ANYCONF_OPTIONS)
  progname_ = "anytun-config";
#else
  progname_ = "anytun";
#endif

  cluster_opts = false;
  connection_opts = false;

  daemonize_ = true;
  username_ = "";
  groupname_ = "";
  chroot_dir_ = "";
  pid_file_ = "";

  debug_ = false;

  file_name_ = "";
  bind_to_.addr = "127.0.0.1";
  bind_to_.port = "2323";

  resolv_addr_type_ = ANY;

  local_.addr = "";
  local_.port = "4444";
  remote_.addr = "";
  remote_.port = "4444";
  local_sync_.addr = "";
  local_sync_.port = "";

  dev_name_ = "";
  dev_type_ = "";
  post_up_script_ = "";

  sender_id_ = 0;
  mux_ = 0;
  seq_window_size_ = 0;

#if !defined(ANYCONF_OPTIONS)
#ifndef NO_CRYPT
  cipher_ = "aes-ctr";
  auth_algo_ = "sha1";
  auth_tag_length_ = 10;
  kd_prf_ = "aes-ctr";
#else
  cipher_ = "null";
  auth_algo_ = "null";
  auth_tag_length_ = 0;
  kd_prf_ = "null";
#endif
#else
  cipher_ = "null";
  auth_algo_ = "null";
  auth_tag_length_ = 0;
  kd_prf_ = "aes-ctr";
#endif
  role_ = ROLE_LEFT;
}

Options::~Options()
{
}

#define NOTHING

#define PARSE_BOOL_PARAM(SHORT, LONG, VALUE, DO_POST)                           \
    else if(str == SHORT || str == LONG) {                                      \
      VALUE = true;                                                             \
      DO_POST;                                                                  \
    }

#define PARSE_INVERSE_BOOL_PARAM(SHORT, LONG, VALUE, DO_POST)                   \
    else if(str == SHORT || str == LONG) {                                      \
      VALUE = false;                                                            \
      DO_POST;                                                                  \
    }

#define PARSE_SIGNED_INT_PARAM(SHORT, LONG, VALUE, DO_POST)                     \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1];                                                         \
      tmp >> VALUE;                                                             \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

#define PARSE_SCALAR_PARAM(SHORT, LONG, VALUE, DO_POST)                         \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1];                                                         \
      tmp >> VALUE;                                                             \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

#define PARSE_SCALAR_PARAM2(SHORT, LONG, VALUE1, VALUE2, DO_POST)               \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argc < 2)                                                              \
        throw syntax_error(str.append(" ").append(argv[i+1]), str.length());    \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      if(argv[i+2][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1 + strlen(argv[i+1]) + 1;               \
        throw syntax_error(str.append(" ").append(argv[i+1]).append(" ").append(argv[i+2]), pos); \
      }                                                                         \
      std::stringstream tmp;                                                    \
      tmp << argv[i+1] << " " << argv[i+2];                                     \
      tmp >> VALUE1;                                                            \
      tmp >> VALUE2;                                                            \
      argc-=2;                                                                  \
      i+=2;                                                                     \
      DO_POST;                                                                  \
    }

#define PARSE_CSLIST_PARAM(SHORT, LONG, LIST, TYPE, DO_POST)                    \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      std::stringstream tmp(argv[i+1]);                                         \
      while (tmp.good())                                                        \
      {                                                                         \
        std::string tmp_line;                                                   \
        getline(tmp,tmp_line,',');                                              \
        LIST.push_back(TYPE(tmp_line));                                         \
      }                                                                         \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

#define PARSE_HEXSTRING_PARAM_SEC(SHORT, LONG, VALUE, DO_POST)                  \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      VALUE = Buffer(std::string(argv[i+1]));                                   \
      for(size_t j=0; j < strlen(argv[i+1]); ++j)                               \
        argv[i+1][j] = '#';                                                     \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

#define PARSE_PHRASE_PARAM_SEC(SHORT, LONG, VALUE, DO_POST)                     \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      VALUE = argv[i+1];                                                        \
      for(size_t j=0; j < strlen(argv[i+1]); ++j)                               \
        argv[i+1][j] = '#';                                                     \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

#define PARSE_STRING_LIST(SHORT, LONG, LIST, DO_POST)                           \
    else if(str == SHORT || str == LONG)                                        \
    {                                                                           \
      if(argc < 1)                                                              \
        throw syntax_error(str, str.length());                                  \
      if(argv[i+1][0] == '-') {                                                 \
        uint32_t pos = str.length() + 1;                                       \
        throw syntax_error(str.append(" ").append(argv[i+1]), pos);             \
      }                                                                         \
      LIST.push_back(argv[i+1]);                                                \
      argc--;                                                                   \
      i++;                                                                      \
      DO_POST;                                                                  \
    }

bool Options::parse(int argc, char* argv[])
{
  WritersLock lock(mutex);

  progname_ = argv[0];
  argc--;
  bool ipv4_only = false, ipv6_only = false;
  std::string role = "";
  for(int i=1; argc > 0; ++i) {
    std::string str(argv[i]);
    argc--;

    if(str == "-h" || str == "--help") {
      printUsage();
      return false;
    } else if(str == "-v" || str == "--version") {
      printVersion();
      return false;
    }

#if defined(ANYTUN_OPTIONS) || defined(ANYCTR_OPTIONS)

#if !defined(_MSC_VER) && !defined(MINGW)
    PARSE_INVERSE_BOOL_PARAM("-D","--nodaemonize", daemonize_, NOTHING)
    PARSE_SCALAR_PARAM("-u","--username", username_, NOTHING)
    PARSE_SCALAR_PARAM("-g","--groupname", groupname_, NOTHING)
    PARSE_SCALAR_PARAM("-C","--chroot", chroot_dir_, NOTHING)
    PARSE_SCALAR_PARAM("-P","--write-pid", pid_file_, NOTHING)
#endif

#endif

    PARSE_STRING_LIST("-L","--log", log_targets_, NOTHING)
    PARSE_BOOL_PARAM("-U","--debug", debug_, NOTHING)

#if defined(ANYCTR_OPTIONS)

    PARSE_SCALAR_PARAM("-f","--file", file_name_, NOTHING)
    PARSE_SCALAR_PARAM("-X","--control-host", bind_to_, NOTHING)

#endif
#if defined(ANYTUN_OPTIONS)

    PARSE_SCALAR_PARAM("-i","--interface", local_.addr, NOTHING)
    PARSE_SCALAR_PARAM("-p","--port", local_.port, NOTHING)
    PARSE_SCALAR_PARAM("-s","--sender-id", sender_id_, NOTHING)

#endif
#if defined(ANYTUN_OPTIONS) || defined(ANYCONF_OPTIONS)

    PARSE_SCALAR_PARAM("-r","--remote-host", remote_.addr, connection_opts = true)
    PARSE_SCALAR_PARAM("-o","--remote-port", remote_.port, connection_opts = true)
    PARSE_BOOL_PARAM("-4","--ipv4-only", ipv4_only, connection_opts = true)
    PARSE_BOOL_PARAM("-6","--ipv6-only", ipv6_only, connection_opts = true)

#endif
#if defined(ANYTUN_OPTIONS)

    PARSE_SCALAR_PARAM("-I","--sync-interface", local_sync_.addr, cluster_opts = true)
    PARSE_SCALAR_PARAM("-S","--sync-port", local_sync_.port, cluster_opts = true)
    PARSE_CSLIST_PARAM("-M","--sync-hosts", remote_sync_hosts_, OptionHost, cluster_opts = true)
    PARSE_CSLIST_PARAM("-X","--control-host", remote_sync_hosts_, OptionHost, cluster_opts = true)

    PARSE_SCALAR_PARAM("-d","--dev", dev_name_, NOTHING)
    PARSE_SCALAR_PARAM("-t","--type", dev_type_, NOTHING)
    PARSE_SCALAR_PARAM("-n","--ifconfig", ifconfig_param_, NOTHING)
    PARSE_SCALAR_PARAM("-x","--post-up-script", post_up_script_, NOTHING)

#endif
#if defined(ANYTUN_OPTIONS) || defined(ANYCONF_OPTIONS)

#ifndef NO_ROUTING
    PARSE_CSLIST_PARAM("-R","--route", routes_, OptionNetwork, connection_opts = true)
#endif

    PARSE_SCALAR_PARAM("-m","--mux", mux_, connection_opts = true)
    PARSE_SCALAR_PARAM("-w","--window-size", seq_window_size_, connection_opts = true)

#ifndef NO_CRYPT
    PARSE_SCALAR_PARAM("-k","--kd-prf", kd_prf_, connection_opts = true)
    PARSE_SCALAR_PARAM("-e","--role", role, connection_opts = true)
#ifndef NO_PASSPHRASE
    PARSE_PHRASE_PARAM_SEC("-E","--passphrase", passphrase_, connection_opts = true)
#endif
    PARSE_HEXSTRING_PARAM_SEC("-K","--key", key_, connection_opts = true)
    PARSE_HEXSTRING_PARAM_SEC("-A","--salt", salt_, connection_opts = true)
#endif

#endif
#if defined(ANYTUN_OPTIONS)

#ifndef NO_CRYPT
    PARSE_SCALAR_PARAM("-c","--cipher", cipher_, NOTHING)
    PARSE_SCALAR_PARAM("-a","--auth-algo", auth_algo_, NOTHING)
    PARSE_SCALAR_PARAM("-b","--auth-tag-length", auth_tag_length_, NOTHING)
#endif

#endif
    else {
      throw syntax_error(str, 0);
    }
  }
  if(ipv4_only && ipv6_only) {
    throw syntax_error("-4 and -6 are mutual exclusive", -1);
  }
  if(ipv4_only) {
    resolv_addr_type_ = IPV4_ONLY;
  }
  if(ipv6_only) {
    resolv_addr_type_ = IPV6_ONLY;
  }

  if(role != "") {
    if(role == "alice" || role == "server" || role == "left") {
      role_ = ROLE_LEFT;
    } else if(role == "bob" || role == "client" || role == "right") {
      role_ = ROLE_RIGHT;
    } else {
      throw syntax_error("unknown role name: " + role, -1);
    }
  }

  if(debug_) {
    log_targets_.push_back("stdout:5");
    daemonize_ = false;
  }

  if(log_targets_.empty()) {
#if !defined(_MSC_VER) && !defined(MINGW)
#if !defined(ANYCONF_OPTIONS)
    log_targets_.push_back(std::string("syslog:3,").append(progname_).append(",daemon"));
#else
    log_targets_.push_back("stderr:2");
#endif
#else
#ifdef WIN_SERVICE
    log_targets_.push_back(std::string("eventlog:3,").append(progname_));
#else
    log_targets_.push_back("stdout:3");
#endif
#endif
  }

  return true;
}

void Options::parse_post()
{
#if defined(ANYTUN_OPTIONS)
  if(cluster_opts && connection_opts) {
    cLog.msg(Log::PRIO_WARNING) << "you have provided options for cluster support as well as connection oriented options, we strongly recommend to use anytun-config and anytun-controld when building a cluster";
  }

  if(cipher_ == "null" && auth_algo_ == "null") {
    kd_prf_ = "null";
  }
  if((cipher_ != "null" || auth_algo_ != "null") && kd_prf_ == "null") {
    cLog.msg(Log::PRIO_WARNING) << "using NULL key derivation with encryption and or authentication enabled!";
  }

  uint32_t tag_len_max = AuthAlgoFactory::getDigestLength(auth_algo_);
  if(!tag_len_max) { auth_tag_length_ = 0; }
  else if(tag_len_max < auth_tag_length_) {
    cLog.msg(Log::PRIO_WARNING) << auth_algo_ << " auth algo can't generate tags of length " << auth_tag_length_ << ", using maximum tag length(" << tag_len_max << ")";
    auth_tag_length_ = tag_len_max;
  }
#endif

  if(dev_name_ == "" && dev_type_ == "") {
    dev_type_ = "tun";
  }
}

void Options::printVersion()
{
#if defined(ANYCTR_OPTIONS)
  std::cout << "anytun-controld";
#elif defined(ANYCONF_OPTIONS)
  std::cout << "anytun-config";
#else
  std::cout << "anytun";
#endif
  std::cout << VERSION_STRING_0 << std::endl;
  std::cout << VERSION_STRING_1 << std::endl;
}

void Options::printUsage()
{
  std::cout << "USAGE:" << std::endl;

#if defined(ANYCTR_OPTIONS)
  std::cout << "anytun-controld " << std::endl;
#elif defined(ANYCONF_OPTIONS)
  std::cout << "anytun-config " << std::endl;
#else
  std::cout << "anytun " << std::endl;
#endif

  std::cout << "   [-h|--help]                         prints this..." << std::endl;
  std::cout << "   [-v|--version]                      print version info and exit" << std::endl;

#if defined(ANYTUN_OPTIONS) || defined(ANYCTR_OPTIONS)

#if !defined(_MSC_VER) && !defined(MINGW)
  std::cout << "   [-D|--nodaemonize]                  don't run in background" << std::endl;
  std::cout << "   [-u|--username] <username>          change to this user" << std::endl;
  std::cout << "   [-g|--groupname] <groupname>        change to this group" << std::endl;
  std::cout << "   [-C|--chroot] <path>                chroot to this directory" << std::endl;
  std::cout << "   [-P|--write-pid] <path>             write pid to this file" << std::endl;
#endif

#endif

  std::cout << "   [-L|--log] <target>:<level>[,<param1>[,<param2>..]]" << std::endl;
  std::cout << "                                       add a log target, can be invoked several times" << std::endl;
  std::cout << "                                       i.e.: stdout:5" << std::endl;
  std::cout << "   [-U|--debug]                        don't daemonize and log to stdout with maximum log level" << std::endl;

#if defined(ANYCTR_OPTIONS)

  std::cout << "   [-f|--file] <path>                  path to input file" << std::endl;
  std::cout << "   [-X|--control-host] < <hostname|ip>[:<port>] | :<port> >" << std::endl;
  std::cout << "                                       local tcp port and or ip address to bind to" << std::endl;

#endif
#if defined(ANYTUN_OPTIONS)

  std::cout << "   [-i|--interface] <hostname|ip>      local anycast ip address to bind to" << std::endl;
  std::cout << "   [-p|--port] <port>                  local anycast(data) port to bind to" << std::endl;
  std::cout << "   [-s|--sender-id ] <sender id>       the sender id to use" << std::endl;

#endif
#if defined(ANYTUN_OPTIONS) || defined(ANYCONF_OPTIONS)

  std::cout << "   [-r|--remote-host] <hostname|ip>    remote host" << std::endl;
  std::cout << "   [-o|--remote-port] <port>           remote port" << std::endl;
  std::cout << "   [-4|--ipv4-only]                    always resolv IPv4 addresses" << std::endl;
  std::cout << "   [-6|--ipv6-only]                    always resolv IPv6 addresses" << std::endl;

#endif
#if defined(ANYTUN_OPTIONS)

  std::cout << "   [-I|--sync-interface] <ip-address>  local unicast(sync) ip address to bind to" << std::endl;
  std::cout << "   [-S|--sync-port] <port>             local unicast(sync) port to bind to" << std::endl;
  std::cout << "   [-M|--sync-hosts] <hostname|ip>[:<port>][,<hostname|ip>[:<port>][...]]"<< std::endl;
  std::cout << "                                       remote hosts to sync with" << std::endl;
  std::cout << "   [-X|--control-host] <hostname|ip>[:<port>]"<< std::endl;
  std::cout << "                                       fetch the config from this host" << std::endl;

  std::cout << "   [-d|--dev] <name>                   device name" << std::endl;
  std::cout << "   [-t|--type] <tun|tap>               device type" << std::endl;
  std::cout << "   [-n|--ifconfig] <local>/<prefix>    the local address for the tun/tap device and the used prefix length" << std::endl;
  std::cout << "   [-x|--post-up-script] <script>      script gets called after interface is created" << std::endl;

#endif
#if defined(ANYTUN_OPTIONS) || defined(ANYCONF_OPTIONS)

#ifndef NO_ROUTING
  std::cout << "   [-R|--route] <net>/<prefix length>  add a route to connection, can be invoked several times" << std::endl;
#endif

  std::cout << "   [-m|--mux] <mux-id>                 the multiplex id to use" << std::endl;
  std::cout << "   [-w|--window-size] <window size>    seqence number window size" << std::endl;

#ifndef NO_CRYPT
  std::cout << "   [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function" << std::endl;
  std::cout << "   [-e|--role] <role>                  left (alice) or right (bob)" << std::endl;
#ifndef NO_PASSPHRASE
  std::cout << "   [-E|--passphrase] <pass phrase>     a passprhase to generate master key and salt from" << std::endl;
#endif
  std::cout << "   [-K|--key] <master key>             master key to use for encryption" << std::endl;
  std::cout << "   [-A|--salt] <master salt>           master salt to use for encryption" << std::endl;
#endif

#endif
#if defined(ANYTUN_OPTIONS)

#ifndef NO_CRYPT
  std::cout << "   [-c|--cipher] <cipher type>         payload encryption algorithm" << std::endl;
  std::cout << "   [-a|--auth-algo] <algo type>        message authentication algorithm" << std::endl;
  std::cout << "   [-b|--auth-tag-length]              length of the auth tag" << std::endl;
#endif

#endif
}

void Options::printOptions()
{
  ReadersLock lock(mutex);

  std::cout << "Options:" << std::endl;
  std::cout << std::endl;
  std::cout << "daemonize = " << daemonize_ << std::endl;
  std::cout << "username = '" << username_ << "'" << std::endl;
  std::cout << "groupname = '" << groupname_ << "'" << std::endl;
  std::cout << "chroot_dir = '" << chroot_dir_ << "'" << std::endl;
  std::cout << "pid_file = '" << pid_file_ << "'" << std::endl;
  std::cout << std::endl;
  std::cout << "log_targets:";
  StringList::const_iterator lit = log_targets_.begin();
  for(; lit != log_targets_.end(); ++lit) {
    std::cout << " '" << *lit << "',";
  }
  std::cout << std::endl;
  std::cout << "debug = " << debug_ << std::endl;
  std::cout << std::endl;
  std::cout << "file_name = '" << file_name_ << "'" << std::endl;
  std::cout << "bind_to.addr = '" << bind_to_.addr << "'" << std::endl;
  std::cout << "bind_to.port = '" << bind_to_.port << "'" << std::endl;
  std::cout << std::endl;
  std::cout << "resolv_addr_type = ";
  switch(resolv_addr_type_) {
  case ANY:
    std::cout <<  "any" << std::endl;
    break;
  case IPV4_ONLY:
    std::cout <<  "ipv4-only" << std::endl;
    break;
  case IPV6_ONLY:
    std::cout <<  "ipv6-only" << std::endl;
    break;
  default:
    std::cout <<  "?" << std::endl;
    break;
  }
  std::cout << std::endl;
  std::cout << "local.addr = '" << local_.addr << "'" << std::endl;
  std::cout << "local.port = '" << local_.port << "'" << std::endl;
  std::cout << "remote.addr = '" << remote_.addr << "'" << std::endl;
  std::cout << "remote.port = '" << remote_.port << "'" << std::endl;
  std::cout << "local_sync.addr = '" << local_sync_.addr << "'" << std::endl;
  std::cout << "local_sync.port = '" << local_sync_.port << "'" << std::endl;
  std::cout << "remote_sync_hosts:" << std::endl;
  HostList::const_iterator hit = remote_sync_hosts_.begin();
  for(; hit != remote_sync_hosts_.end(); ++hit) {
    std::cout << "  '" << hit->addr << "','" << hit->port << "'" << std::endl;
  }
  std::cout << std::endl;
  std::cout << "dev_name = '" << dev_name_ << "'" << std::endl;
  std::cout << "dev_type = '" << dev_type_ << "'" << std::endl;
  std::cout << "ifconfig_param_local = '" << ifconfig_param_.net_addr << "/" << ifconfig_param_.prefix_length << "'" << std::endl;
  std::cout << "post_up_script = '" << post_up_script_ << "'" << std::endl;
  std::cout << "routes:" << std::endl;
  NetworkList::const_iterator rit;
  for(rit = routes_.begin(); rit != routes_.end(); ++rit) {
    std::cout << "  " << rit->net_addr << "/" << rit->prefix_length << std::endl;
  }
  std::cout << std::endl;
  std::cout << "sender_id = '" << sender_id_ << "'" << std::endl;
  std::cout << "mux_id = " << mux_ << std::endl;
  std::cout << "seq_window_size = '" << seq_window_size_ << "'" << std::endl;
  std::cout << std::endl;
  std::cout << "cipher = '" << cipher_ << "'" << std::endl;
  std::cout << "auth_algo = '" << auth_algo_ << "'" << std::endl;
  std::cout << "auth_tag_length = " << auth_tag_length_ << std::endl;
  std::cout << "kd_prf = '" << kd_prf_ << "'" << std::endl;
  std::cout << "role = ";
  switch(role_) {
  case ROLE_LEFT:
    std::cout << "left" << std::endl;
    break;
  case ROLE_RIGHT:
    std::cout << "right" << std::endl;
    break;
  default:
    std::cout << "??" << std::endl;
    break;
  }
  std::cout << "passphrase = '" << passphrase_ << "'" << std::endl;
  std::cout << "key = " << key_.getHexDumpOneLine() << std::endl;
  std::cout << "salt = " << salt_.getHexDumpOneLine() << std::endl;
}



std::string Options::getProgname()
{
  ReadersLock lock(mutex);
  return progname_;
}

Options& Options::setProgname(std::string p)
{
  WritersLock lock(mutex);
  progname_ = p;
  return *this;
}

bool Options::getDaemonize()
{
  ReadersLock lock(mutex);
  return daemonize_;
}

Options& Options::setDaemonize(bool d)
{
  WritersLock lock(mutex);
  daemonize_ = d;
  return *this;
}

std::string Options::getUsername()
{
  ReadersLock lock(mutex);
  return username_;
}

Options& Options::setUsername(std::string u)
{
  WritersLock lock(mutex);
  username_ = u;
  return *this;
}

std::string Options::getGroupname()
{
  ReadersLock lock(mutex);
  return groupname_;
}

Options& Options::setGroupname(std::string g)
{
  WritersLock lock(mutex);
  groupname_ = g;
  return *this;
}

std::string Options::getChrootDir()
{
  ReadersLock lock(mutex);
  return chroot_dir_;
}

Options& Options::setChrootDir(std::string c)
{
  WritersLock lock(mutex);
  chroot_dir_ = c;
  return *this;
}

std::string Options::getPidFile()
{
  ReadersLock lock(mutex);
  return pid_file_;
}

Options& Options::setPidFile(std::string p)
{
  WritersLock lock(mutex);
  pid_file_ = p;
  return *this;
}


StringList Options::getLogTargets()
{
  ReadersLock lock(mutex);
  return log_targets_;
}

bool Options::getDebug()
{
  ReadersLock lock(mutex);
  return debug_;
}

Options& Options::setDebug(bool d)
{
  WritersLock lock(mutex);
  debug_ = d;
  return *this;
}


std::string Options::getFileName()
{
  ReadersLock lock(mutex);
  return file_name_;
}

Options& Options::setFileName(std::string f)
{
  WritersLock lock(mutex);
  file_name_ = f;
  return *this;
}

std::string Options::getBindToAddr()
{
  ReadersLock lock(mutex);
  return bind_to_.addr;
}

Options& Options::setBindToAddr(std::string b)
{
  WritersLock lock(mutex);
  bind_to_.addr = b;
  return *this;
}

std::string Options::getBindToPort()
{
  ReadersLock lock(mutex);
  return bind_to_.port;
}

Options& Options::setBindToPort(std::string b)
{
  WritersLock lock(mutex);
  bind_to_.port = b;
  return *this;
}


ResolvAddrType Options::getResolvAddrType()
{
  ReadersLock lock(mutex);
  return resolv_addr_type_;
}

Options& Options::setResolvAddrType(ResolvAddrType r)
{
  WritersLock lock(mutex);
  resolv_addr_type_ = r;
  return *this;
}

std::string Options::getLocalAddr()
{
  ReadersLock lock(mutex);
  return local_.addr;
}

Options& Options::setLocalAddr(std::string l)
{
  WritersLock lock(mutex);
  local_.addr = l;
  return *this;
}

std::string Options::getLocalPort()
{
  ReadersLock lock(mutex);
  return local_.port;
}

Options& Options::setLocalPort(std::string l)
{
  WritersLock lock(mutex);
  local_.port = l;
  return *this;
}

std::string Options::getRemoteAddr()
{
  ReadersLock lock(mutex);
  return remote_.addr;
}

Options& Options::setRemoteAddr(std::string r)
{
  WritersLock lock(mutex);
  remote_.addr = r;
  return *this;
}

std::string Options::getRemotePort()
{
  ReadersLock lock(mutex);
  return remote_.port;
}

Options& Options::setRemotePort(std::string r)
{
  WritersLock lock(mutex);
  remote_.port = r;
  return *this;
}

std::string Options::getLocalSyncAddr()
{
  ReadersLock lock(mutex);
  return local_sync_.addr;
}

Options& Options::setLocalSyncAddr(std::string l)
{
  WritersLock lock(mutex);
  local_sync_.addr = l;
  return *this;
}

std::string Options::getLocalSyncPort()
{
  ReadersLock lock(mutex);
  return local_sync_.port;
}

Options& Options::setLocalSyncPort(std::string l)
{
  WritersLock lock(mutex);
  local_sync_.port = l;
  return *this;
}

HostList Options::getRemoteSyncHosts()
{
  ReadersLock lock(mutex);
  return remote_sync_hosts_;
}



std::string Options::getDevName()
{
  ReadersLock lock(mutex);
  return dev_name_;
}

Options& Options::setDevName(std::string d)
{
  WritersLock lock(mutex);
  dev_name_ = d;
  return *this;
}

std::string Options::getDevType()
{
  ReadersLock lock(mutex);
  return dev_type_;
}

Options& Options::setDevType(std::string d)
{
  WritersLock lock(mutex);
  dev_type_ = d;
  return *this;
}

OptionNetwork Options::getIfconfigParam()
{
  ReadersLock lock(mutex);
  return ifconfig_param_;
}

Options& Options::setIfconfigParam(OptionNetwork i)
{
  WritersLock lock(mutex);
  ifconfig_param_ = i;
  return *this;
}

std::string Options::getPostUpScript()
{
  ReadersLock lock(mutex);
  return post_up_script_;
}

Options& Options::setPostUpScript(std::string p)
{
  WritersLock lock(mutex);
  post_up_script_ = p;
  return *this;
}

NetworkList Options::getRoutes()
{
  ReadersLock lock(mutex);
  return routes_;
}



sender_id_t Options::getSenderId()
{
  ReadersLock lock(mutex);
  return sender_id_;
}

Options& Options::setSenderId(sender_id_t s)
{
  WritersLock lock(mutex);
  sender_id_ = s;
  return *this;
}

mux_t Options::getMux()
{
  ReadersLock lock(mutex);
  return mux_;
}

Options& Options::setMux(mux_t m)
{
  WritersLock lock(mutex);
  mux_ = m;
  return *this;
}

window_size_t Options::getSeqWindowSize()
{
  ReadersLock lock(mutex);
  return seq_window_size_;
}

Options& Options::setSeqWindowSize(window_size_t s)
{
  WritersLock lock(mutex);
  seq_window_size_ = s;
  return *this;
}



std::string Options::getCipher()
{
  ReadersLock lock(mutex);
  return cipher_;
}

Options& Options::setCipher(std::string c)
{
  WritersLock lock(mutex);
  cipher_ = c;
  return *this;
}

std::string Options::getAuthAlgo()
{
  ReadersLock lock(mutex);
  return auth_algo_;
}

Options& Options::setAuthAlgo(std::string a)
{
  WritersLock lock(mutex);
  auth_algo_ = a;
  return *this;
}

uint32_t Options::getAuthTagLength()
{
  ReadersLock lock(mutex);
  return auth_tag_length_;
}

Options& Options::setAuthTagLength(uint32_t a)
{
  WritersLock lock(mutex);
  auth_tag_length_ = a;
  return *this;
}


std::string Options::getKdPrf()
{
  ReadersLock lock(mutex);
  return kd_prf_;
}

Options& Options::setKdPrf(std::string k)
{
  WritersLock lock(mutex);
  kd_prf_ = k;
  return *this;
}

role_t Options::getRole()
{
  ReadersLock lock(mutex);
  return role_;
}

Options& Options::setRole(role_t r)
{
  WritersLock lock(mutex);
  role_ = r;
  return *this;
}

std::string Options::getPassphrase()
{
  ReadersLock lock(mutex);
  return passphrase_;
}

Options& Options::setPassphrase(std::string p)
{
  WritersLock lock(mutex);
  passphrase_ = p;
  return *this;
}

Buffer Options::getKey()
{
  ReadersLock lock(mutex);
  return key_;
}

Options& Options::setKey(std::string k)
{
  WritersLock lock(mutex);
  key_ = k;
  return *this;
}

Buffer Options::getSalt()
{
  ReadersLock lock(mutex);
  return salt_;
}

Options& Options::setSalt(std::string s)
{
  WritersLock lock(mutex);
  salt_ = s;
  return *this;
}
