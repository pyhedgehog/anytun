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

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include <list>

class syntax_error : public std::runtime_error
{
public:
  syntax_error(std::string t, u_int32_t p) : runtime_error(t), pos(p) {};
  u_int32_t pos;
};
std::ostream& operator<<(std::ostream& stream, syntax_error const& error);

class OptionHost
{
public:
  OptionHost() : addr(""), port("") {};
  OptionHost(std::string addrPort) { init(addrPort); };
  OptionHost(std::string a, std::string p) : addr(a), port(p) {};

  void init(std::string addrPort);

  std::string addr;
	std::string port;
};
typedef std::list<OptionHost> HostList;
std::istream& operator>>(std::istream& stream, OptionHost& host);

class OptionRoute
{
public:
  OptionRoute() : net_addr(""), prefix_length(0) {};
  OptionRoute(std::string route) { init(route); };
  OptionRoute(std::string n, u_int16_t p) : net_addr(n), prefix_length(p) {};

  void init(std::string route);

  std::string net_addr;
  u_int16_t prefix_length;
};
typedef std::list<OptionRoute> RouteList;
std::istream& operator>>(std::istream& stream, OptionRoute& route);

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

  std::string getLocalAddr();
  Options& setLocalAddr(std::string l);
  std::string getLocalPort();
  Options& setLocalPort(std::string l);
  std::string getRemoteAddr();
  Options& setRemoteAddr(std::string r);
  std::string getRemotePort();
  Options& setRemotePort(std::string r);

  std::string getLocalSyncAddr();
  Options& setLocalSyncAddr(std::string l);
  std::string getLocalSyncPort();
  Options& setLocalSyncPort(std::string l);
	HostList getRemoteSyncHosts();

  std::string getDevName();
  Options& setDevName(std::string d);
  std::string getDevType();
  Options& setDevType(std::string d);
  std::string getIfconfigParamLocal();
  Options& setIfconfigParamLocal(std::string i);
  std::string getIfconfigParamRemoteNetmask();
  Options& setIfconfigParamRemoteNetmask(std::string i);
  std::string getPostUpScript();
  Options& setPostUpScript(std::string p);
  RouteList getRoutes();

  sender_id_t getSenderId();
  Options& setSenderId(sender_id_t s);
  mux_t getMux();
  Options& setMux(mux_t m);
  window_size_t getSeqWindowSize();
  Options& setSeqWindowSize(window_size_t s);

  std::string getCipher();
  Options& setCipher(std::string c);
  std::string getAuthAlgo();
  Options& setAuthAlgo(std::string a);
  std::string getKdPrf();
  Options& setKdPrf(std::string k);
  int8_t getLdKdr();
  Options& setLdKdr(int8_t l);
  Options& setKey(std::string k);
  Buffer getKey();
  Options& setSalt(std::string s);
  Buffer getSalt();


private:
  Options();
  ~Options();
  Options(const Options &l);
  void operator=(const Options &l);

  static Options* inst;
  static ::Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(Options::inst != 0)
        delete Options::inst;
    }
  };
  friend class instanceCleaner;

  ::Mutex mutex;

  std::string progname_;
  bool daemonize_;
  bool chroot_;
  std::string username_;
  std::string chroot_dir_;
  std::string pid_file_;

  std::string file_name_;
  OptionHost bind_to_;

  std::string local_addr_;
  std::string local_port_;
  std::string remote_addr_;
  std::string remote_port_;

  std::string local_sync_addr_;
  std::string local_sync_port_;
	HostList remote_sync_hosts_;

  std::string dev_name_;
  std::string dev_type_;
  std::string ifconfig_param_local_;
  std::string ifconfig_param_remote_netmask_;
  std::string post_up_script_;
  RouteList routes_;

  sender_id_t sender_id_;
  mux_t mux_;
  window_size_t seq_window_size_;

  std::string cipher_;
  std::string auth_algo_;
  std::string kd_prf_;
  int8_t ld_kdr_;
  Buffer key_;
  Buffer salt_;
};

extern Options& gOpt;

#endif
