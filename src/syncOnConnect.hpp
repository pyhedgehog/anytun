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

#ifndef ANYTUN_syncOnConnect_hpp_INCLUDED
#define ANYTUN_syncOnConnect_hpp_INCLUDED

// TODO required headers

void syncOnConnect(SyncTcpConnection* connptr)
{
  //TODO Locking here
  ConnectionList& cl_(gConnectionList);
  ConnectionMap::iterator cit = cl_.getBeginUnlocked();
  for(; cit!=cl_.getEndUnlocked(); ++cit) {
    std::ostringstream sout;
    boost::archive::text_oarchive oa(sout);
    const SyncCommand scom(cl_,cit->first);
    oa << scom;
    std::stringstream lengthout;
    lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
    connptr->Send(lengthout.str());
    connptr->Send(sout.str());
  }
  //TODO Locking here
  network_address_type_t types[] = {ipv4,ipv6,ethernet};
  for(int types_idx=0; types_idx<3; types_idx++) {
    network_address_type_t type = types[types_idx];
    RoutingMap::iterator it = gRoutingTable.getBeginUnlocked(type);
    for(; it!=gRoutingTable.getEndUnlocked(type); ++it) {
      NetworkPrefix tmp(it->first);
      std::ostringstream sout;
      boost::archive::text_oarchive oa(sout);
      const SyncCommand scom(tmp);
      oa << scom;
      std::stringstream lengthout;
      lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
      connptr->Send(lengthout.str());
      connptr->Send(sout.str());
    }
  }
}

#endif
