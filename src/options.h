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

#ifndef ANYTUN_options_h_INCLUDED
#define ANYTUN_options_h_INCLUDED

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include <list>

class syntax_error : public std::runtime_error
{
public:
  syntax_error(std::string t, int32_t p) : runtime_error(t), pos(p) {};
  int32_t pos;
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

class OptionNetwork
{
public:
  OptionNetwork() : net_addr(""), prefix_length(0) {};
  OptionNetwork(std::string network) { init(network); };
  OptionNetwork(std::string n, uint16_t p) : net_addr(n), prefix_length(p) {};

  void init(std::string network);

  std::string net_addr;
  uint16_t prefix_length;
};
typedef std::list<OptionNetwork> NetworkList;
std::istream& operator>>(std::istream& stream, OptionNetwork& network);

typedef std::list<std::string> StringList;

typedef enum { ROLE_LEFT, ROLE_RIGHT } role_t;
std::ostream& operator<<(std::ostream& stream, role_t const& role);

class Options
{
public:
  static Options& instance();

  bool parse(int argc, char* argv[]);
  void parse_post();
  void printVersion();
  void printUsage();
  void printOptions();

  std::string getProgname();
  Options& setProgname(std::string p);
  bool getDaemonize();
  Options& setDaemonize(bool d);
  std::string getUsername();
  Options& setUsername(std::string u);
  std::string getGroupname();
  Options& setGroupname(std::string g);
  std::string getChrootDir();
  Options& setChrootDir(std::string c);
  std::string getPidFile();
  Options& setPidFile(std::string p);

  StringList getLogTargets();
  bool getDebug();
  Options& setDebug(bool d);

  std::string getFileName();
  Options& setFileName(std::string f);
  std::string getBindToAddr();
  Options& setBindToAddr(std::string b);
  std::string getBindToPort();
  Options& setBindToPort(std::string b);

  ResolvAddrType getResolvAddrType();
  Options& setResolvAddrType(ResolvAddrType r);
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
  OptionNetwork getIfconfigParam();
  Options& setIfconfigParam(OptionNetwork i);
  std::string getPostUpScript();
  Options& setPostUpScript(std::string p);
  NetworkList getRoutes();

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
  uint32_t getAuthTagLength();
  Options& setAuthTagLength(uint32_t a);
  std::string getKdPrf();
  Options& setKdPrf(std::string k);
  role_t getRole();
  Options& setRole(role_t r);
  std::string getPassphrase();
  Options& setPassphrase(std::string p);
  Options& setKey(std::string k);
  Buffer getKey();
  Options& setSalt(std::string s);
  Buffer getSalt();


private:
  Options();
  ~Options();
  Options(const Options& l);
  void operator=(const Options& l);

  static Options* inst;
  static ::Mutex instMutex;
  class instanceCleaner
  {
  public:
    ~instanceCleaner() {
      if(Options::inst != 0) {
        delete Options::inst;
      }
    }
  };
  friend class instanceCleaner;

  ::SharedMutex mutex;


  bool cluster_opts;
  bool connection_opts;

  std::string progname_;
  bool daemonize_;
  std::string username_;
  std::string groupname_;
  std::string chroot_dir_;
  std::string pid_file_;

  StringList log_targets_;
  bool debug_;

  std::string file_name_;
  OptionHost bind_to_;

  ResolvAddrType resolv_addr_type_;
  OptionHost local_;
  OptionHost remote_;

  OptionHost local_sync_;
  HostList remote_sync_hosts_;

  std::string dev_name_;
  std::string dev_type_;
  OptionNetwork ifconfig_param_;
  std::string post_up_script_;
  NetworkList routes_;

  sender_id_t sender_id_;
  mux_t mux_;
  window_size_t seq_window_size_;

  std::string cipher_;
  std::string auth_algo_;
  uint32_t auth_tag_length_;
  std::string kd_prf_;
  role_t role_;
  std::string passphrase_;
  Buffer key_;
  Buffer salt_;
};

extern Options& gOpt;

#endif
