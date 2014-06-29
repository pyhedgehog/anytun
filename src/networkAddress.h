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

#ifndef ANYTUN_networkAddress_h_INCLUDED
#define ANYTUN_networkAddress_h_INCLUDED

// TODO not required here
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"
#include "datatypes.h"

#include <string>
#include <boost/asio.hpp>
#include <boost/array.hpp>

typedef boost::array<unsigned char,6> ethernet_bytes_type;
typedef boost::asio::ip::address_v4::bytes_type ipv4_bytes_type;
typedef boost::asio::ip::address_v6::bytes_type ipv6_bytes_type;

enum network_address_type_t {
  ipv4=0,
  ipv6=1,
  ethernet=2
};

class NetworkAddress
{
public:
  NetworkAddress();
  NetworkAddress(const NetworkAddress&);
  NetworkAddress(const std::string&);
  NetworkAddress(boost::asio::ip::address_v6);
  NetworkAddress(boost::asio::ip::address_v4);
  NetworkAddress(uint64_t);
  NetworkAddress(const network_address_type_t type, const std::string& address);
  ~NetworkAddress();
  void setNetworkAddress(const network_address_type_t type, const std::string& address);
  void setNetworkAddress(boost::asio::ip::address_v4);
  void setNetworkAddress(boost::asio::ip::address_v6);
  void setNetworkAddress(uint64_t);
  network_address_type_t getNetworkAddressType() const;
  std::string toString() const;
  bool operator<(const NetworkAddress& s) const;
  ipv4_bytes_type to_bytes_v4() const;
  ipv6_bytes_type to_bytes_v6() const;
  ethernet_bytes_type to_bytes_ethernet() const;
  const boost::asio::ip::address_v4& getNetworkAddressV4() const;
  const boost::asio::ip::address_v6& getNetworkAddressV6() const;
  const uint64_t getNetworkAdrressEther() const;
protected:
  Mutex mutex_;
  boost::asio::ip::address_v4 ipv4_address_;
  boost::asio::ip::address_v6 ipv6_address_;
  uint64_t ethernet_address_;
  network_address_type_t network_address_type_;
private:
  NetworkAddress operator=(const NetworkAddress& s);
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive& ar, const unsigned int version) {
    ar& network_address_type_;
    if(network_address_type_==ipv4) {
      std::string ip(ipv4_address_.to_string());
      ar& ip;
      ipv4_address_=boost::asio::ip::address_v4::from_string(ip);
    }
    if(network_address_type_==ipv6) {
      std::string ip(ipv6_address_.to_string());
      ar& ip;
      ipv6_address_=boost::asio::ip::address_v6::from_string(ip);
    }
    if(network_address_type_==ethernet) {
      ar& ethernet_address_;
    }
  }
};

//			for(int i=0;i<4;i++)
//#if defined(__GNUC__) && defined(__linux__)
//				ar & ipv6_address_.s6_addr32;
//#elif defined(__GNUC__) && defined(__OpenBSD__)
//        ar & ipv6_address_.__u6_addr.__u6_addr32;
//#else
// #error Target not supported
//#endif
#endif
