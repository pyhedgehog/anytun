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

typedef struct
{
  std::string host;
	std::string port;
} OptionConnectTo;

typedef std::list<OptionConnectTo>  ConnectToList;

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
  sender_id_t getSenderId();
  Options& setSenderId(sender_id_t s);
  std::string getLocalAddr();
  Options& setLocalAddr(std::string l);
  std::string getLocalSyncAddr();
  Options& setLocalSyncAddr(std::string l);
  std::string getRemoteSyncAddr();
  Options& setRemoteSyncAddr(std::string l);
  std::string getRemoteSyncPort();
  Options& setRemoteSyncPort(std::string l);
  std::string getLocalPort();
  Options& setLocalPort(std::string l);
  std::string getRemoteAddr();
  Options& setRemoteAddr(std::string r);
  std::string getLocalSyncPort();
  Options& setLocalSyncPort(std::string l);
  std::string getRemotePort();
  Options& setRemotePort(std::string r);
  Options& setRemoteAddrPort(std::string addr, std::string port);
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
  window_size_t getSeqWindowSize();
  Options& setSeqWindowSize(window_size_t s);
  std::string getCipher();
  Options& setCipher(std::string c);
  std::string getKdPrf();
  Options& setKdPrf(std::string k);
  std::string getAuthAlgo();
  Options& setAuthAlgo(std::string a);
	ConnectToList getConnectTo();
  Options& setMux(u_int16_t m);
  u_int16_t getMux();
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

  static bool splitAndAddHostPort(std::string hostPort, ConnectToList& list);

  ::Mutex mutex;

	ConnectToList connect_to_;
  std::string progname_;
  bool daemonize_;
  bool chroot_;
  std::string username_;
  std::string chroot_dir_;
  std::string pid_file_;
  sender_id_t sender_id_;
  std::string local_addr_;
  std::string local_sync_addr_;
  std::string local_port_;
  std::string local_sync_port_;
  std::string remote_sync_addr_;
  std::string remote_sync_port_;
  std::string remote_addr_;
  std::string remote_port_;
  std::string dev_name_;
  std::string dev_type_;
  std::string ifconfig_param_local_;
  std::string ifconfig_param_remote_netmask_;
  std::string post_up_script_;
  window_size_t seq_window_size_;
  std::string cipher_;
  std::string kd_prf_;
  std::string auth_algo_;
  u_int16_t mux_;
  Buffer key_;
  Buffer salt_;
};

extern Options& gOpt;

#endif
