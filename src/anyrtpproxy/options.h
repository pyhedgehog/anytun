/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
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
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include "../threadUtils.hpp"
#include <list>
#include <sstream>

typedef struct OptionConnectTo {
  std::string host;
  std::string port;
};

typedef std::list<OptionConnectTo>  ConnectToList;

class Host
{
public:
  Host(std::string addr, std::string port) : addr_(addr), port_(port) {}
  Host(std::string addr_port) {
    splitAndSetAddrPort(addr_port);
  }
  std::string toString() const {
    std::ostringstream oss;
    oss << addr_ << ":" << port_;
    return oss.str();
  }

  std::string addr_;
  std::string port_;

protected:
  void splitAndSetAddrPort(std::string addr_port);
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
  std::string getPidFile();
  bool getDaemonize();
  Host getControlInterface();
  std::string getLocalAddr();
  Options& setLocalAddr(std::string l);
  std::string getLocalSyncAddr();
  Options& setLocalSyncAddr(std::string l);
  std::string getLocalSyncPort();
  Options& setLocalSyncPort(std::string l);
  uint16_t getRtpStartPort();
  Options& setRtpStartPort(uint16_t l);
  uint16_t getRtpEndPort();
  Options& setRtpEndPort(uint16_t l);
  ConnectToList getConnectTo();

private:
  Options();
  ~Options();
  Options(const Options& l);
  void operator=(const Options& l);
  bool sanityCheck();

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

  ::Mutex mutex;

  std::string progname_;
  bool chroot_;
  bool nat_;
  bool no_nat_once_;
  std::string username_;
  std::string chroot_dir_;
  std::string pid_file_;
  bool daemonize_;
  std::string local_sync_addr_;
  std::string local_sync_port_;
  std::string local_addr_;
  uint16_t rtp_start_port_;
  uint16_t rtp_end_port_;
  ConnectToList connect_to_;
  Host control_interface_;
};

extern Options& gOpt;

#endif
