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

#include "threadUtils.hpp"
#include "datatypes.h"
#include <exception>

#include "networkAddress.h"
#include "anytunError.h"

NetworkAddress::NetworkAddress():ipv4_address_(),ipv6_address_()
{
  network_address_type_=ipv4;
}

NetworkAddress::NetworkAddress(const NetworkAddress& ref) : mutex_(),ipv4_address_(ref.ipv4_address_),ipv6_address_(ref.ipv6_address_),ethernet_address_(ref.ethernet_address_),network_address_type_(ref.network_address_type_)
{
}

NetworkAddress::NetworkAddress(const std::string& address)
{
  boost::asio::ip::address addr = boost::asio::ip::address::from_string(address);
  if(addr.is_v4()) {
    network_address_type_=ipv4;
    ipv4_address_ = addr.to_v4();
  } else {
    network_address_type_=ipv6;
    ipv6_address_ = addr.to_v6();
  }
}

NetworkAddress::NetworkAddress(boost::asio::ip::address_v6 ipv6_address)
{
  network_address_type_=ipv6;
  ipv6_address_ = ipv6_address;
}

NetworkAddress::NetworkAddress(boost::asio::ip::address_v4 ipv4_address)
{
  network_address_type_=ipv4;
  ipv4_address_ = ipv4_address;
}

NetworkAddress::NetworkAddress(uint64_t ethernet_address)
{
  network_address_type_=ethernet;
  ethernet_address_=ethernet_address;
}


NetworkAddress::~NetworkAddress()
{
}

NetworkAddress::NetworkAddress(const network_address_type_t type, const std::string& address)
{
  setNetworkAddress(type, address);
}

void NetworkAddress::setNetworkAddress(const network_address_type_t type, const std::string& address)
{
  if(type==ipv4) {
    ipv4_address_=boost::asio::ip::address_v4::from_string(address);
  } else if(type==ipv6) {
    ipv6_address_=boost::asio::ip::address_v6::from_string(address);
  } else if(type==ethernet) {
    //TODO
  } else {
    //TODO
  }
  network_address_type_ = type;
}

void NetworkAddress::setNetworkAddress(boost::asio::ip::address_v4 addr)
{
  network_address_type_=ipv4;
  ipv4_address_ = addr;
}

void NetworkAddress::setNetworkAddress(boost::asio::ip::address_v6 addr)
{
  network_address_type_=ipv6;
  ipv6_address_ = addr;
}

void NetworkAddress::setNetworkAddress(uint64_t addr)
{
  network_address_type_=ethernet;
  ethernet_address_=addr;
}

network_address_type_t NetworkAddress::getNetworkAddressType() const
{
  return network_address_type_;
}

const boost::asio::ip::address_v4& NetworkAddress::getNetworkAddressV4() const
{
  if(network_address_type_ != ipv4) {
    AnytunError::throwErr() << "wrong address type";
  }

  return ipv4_address_;
}

const boost::asio::ip::address_v6& NetworkAddress::getNetworkAddressV6() const
{
  if(network_address_type_ != ipv6) {
    AnytunError::throwErr() << "wrong address type";
  }

  return ipv6_address_;
}

const uint64_t NetworkAddress::getNetworkAdrressEther() const
{
  if(network_address_type_ != ethernet) {
    AnytunError::throwErr() << "wrong address type";
  }

  return ethernet_address_;
}

std::string NetworkAddress::toString() const
{
  if(network_address_type_==ipv4) {
    return ipv4_address_.to_string();
  } else if(network_address_type_==ipv6) {
    return ipv6_address_.to_string();
  } else if(network_address_type_==ethernet) {
    // TODO
  }
  return std::string("");
}

ipv4_bytes_type	NetworkAddress::to_bytes_v4() const
{
  return ipv4_address_.to_bytes();
}

ipv6_bytes_type	NetworkAddress::to_bytes_v6() const
{
  return ipv6_address_.to_bytes();
}

ethernet_bytes_type	NetworkAddress::to_bytes_ethernet() const
{
  boost::array<unsigned char,6> result;
  uint64_t ether=ethernet_address_;
  for(int i = 0; i < 6; i++) {
    result[i] = (unsigned char)(ether & 0xff);
    ether >>= 8;
  }
  return result;
}

bool NetworkAddress::operator<(const NetworkAddress& right) const
{
  if(network_address_type_!=right.network_address_type_) {
    AnytunError::throwErr() << "NetworkAddress::operator<() address types don't match";
  }
  if(network_address_type_==ipv4) {
    return (ipv4_address_ < right.ipv4_address_);
  } else if(network_address_type_==ipv6) {
    return (ipv6_address_ < right.ipv6_address_);
  } else if(network_address_type_==ethernet) {
    return (ethernet_address_ < right.ethernet_address_);
  } else {
    //TODO
  }
  return false;
}

