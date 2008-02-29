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

#ifndef _ANYCTR_OPTIONS_H_
#define _ANYCTR_OPTIONS_H_

#include "datatypes.h"
#include "buffer.h"
#include "threadUtils.hpp"
#include <list>

typedef struct OptionConnectTo
{
  std::string host;
	uint16_t port;
};

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
  std::string getRemoteAddr();
  Options& setRemoteAddr(std::string r);
  u_int16_t getRemotePort();
  Options& setRemotePort(u_int16_t r);
  Options& setRemoteAddrPort(std::string addr, u_int16_t port);
  std::string getIfconfigParamRemoteNetmask();
  Options& setIfconfigParamRemoteNetmask(std::string i);
  window_size_t getSeqWindowSize();
  Options& setSeqWindowSize(window_size_t s);
  std::string getKdPrf();
  Options& setKdPrf(std::string k);
  Options& setMux(u_int16_t m);
  u_int16_t getMux();
  Options& setKey(std::string k);
  Buffer getKey();
  Options& setSalt(std::string s);
  Buffer getSalt();
  Options& setNetworkPrefixLength(u_int16_t l);
  u_int16_t getNetworkPrefixLength();

private:
  Options();
  ~Options();
  Options(const Options &l);
  void operator=(const Options &l);

  static Options* inst;
  static Mutex instMutex;
  class instanceCleaner {
    public: ~instanceCleaner() {
      if(Options::inst != 0)
        delete Options::inst;
    }
  };
  friend class instanceCleaner;

  Mutex mutex;

	ConnectToList connect_to_;
  std::string progname_;
  std::string remote_addr_;
  u_int16_t remote_port_;
  std::string ifconfig_param_local_;
  std::string ifconfig_param_remote_netmask_;
  window_size_t seq_window_size_;
  std::string kd_prf_;
  u_int16_t mux_;
  u_int16_t network_prefix_length_;
  Buffer key_;
  Buffer salt_;
};

extern Options& gOpt;

#endif
