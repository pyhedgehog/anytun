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

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include "../threadUtils.hpp"
#include <list>
#include <sstream>

typedef struct OptionConnectTo
{
  std::string host;
  uint16_t port;
};

typedef std::list<OptionConnectTo>  ConnectToList;

class Host
{
public:
  Host(std::string addr, u_int16_t port) : addr_(addr), port_(port) {}
  Host(std::string addr_port)
  {
    std::istringstream iss(addr_port);
    getline(iss, addr_, ':');
    if(!(iss >> port_)) port_ = 0;
  } 
  std::string toString() const
  {
    std::ostringstream oss;
    oss << addr_ << ":" << port_;
    return oss.str();
  }
  
  std::string addr_;
	u_int16_t port_;
};

typedef std::list<Host> HostList;

class Options
{
public:
  static Options& instance();

  bool parse(int argc, char* argv[]);
  void printUsage();
  void printOptions();

  std::string getProgname();
  bool getChroot();
  bool getNat();
  bool getNoNatOnce();
  std::string getUsername();
  std::string getChrootDir();
  bool getDaemonize();
  Host getControlInterface();
  u_int16_t getLocalSyncPort();
	Options& setLocalSyncPort(u_int16_t l);
  u_int16_t getRtpStartPort();
	Options& setRtpStartPort(u_int16_t l);
  u_int16_t getRtpEndPort();
	Options& setRtpEndPort(u_int16_t l);
  ConnectToList getConnectTo();

private:
  Options();
  ~Options();
  Options(const Options &l);
  void operator=(const Options &l);
  bool sanityCheck();

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
  bool chroot_;
  bool nat_;
  bool no_nat_once_;
  std::string username_;
  std::string chroot_dir_;
  bool daemonize_;
	u_int16_t local_sync_port_;
	u_int16_t rtp_start_port_;
	u_int16_t rtp_end_port_;
	ConnectToList connect_to_;
  Host control_interface_;
};

extern Options& gOpt;

#endif
