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

class Options
{
public:
  Options();
  bool parse(int argc, char* argv[]);
  void printUsage() const;
  void printOptions() const;

  std::string getProgname() const;
  sender_id_t getSenderId() const;
  std::string getLocalAddr() const;
  u_int16_t getLocalPort() const;
  std::string getRemoteAddr() const;
  u_int16_t getRemotePort() const;
  std::string getDevName() const;
  std::string getIfconfigParamLocal() const;
  std::string getIfconfigParamRemoteNetmask() const;

private:
  std::string progname_;
  sender_id_t sender_id_;
  std::string local_addr_;
  u_int16_t local_port_;
  std::string remote_addr_;
  u_int16_t remote_port_;
  std::string dev_name_;
  std::string ifconfig_param_local_;
  std::string ifconfig_param_remote_netmask_;
};

#endif
