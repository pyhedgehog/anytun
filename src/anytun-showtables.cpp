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

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "keyDerivation.h"
#include "seqWindow.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"
#include "syncCommand.h"

#include <sstream>
#include <iostream>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


void output(ConnectionList &cl)
{
	if( !cl.empty() )
	{
		ConnectionMap::iterator it = cl.getBeginUnlocked();
		mux_t mux = it->first;
		ConnectionParam &conn( it->second );
		std::cout << "Client " << mux << ": " ;
		if( conn.remote_end_==PacketSourceEndpoint())
		{
			std::cout<< "not registered";
		} else {
		  std::cout<< conn.remote_end_;
		}
		std::cout << std::endl;
    //std::cout << "Connection: Keyderivation-Type: " << conn.kd_.printType() << std::endl;
    cl.clear();
	} 
  else if( !gRoutingTable.empty() ) 
  {
		RoutingMap::iterator it = gRoutingTable.getBeginUnlocked();
		NetworkPrefix pref( it->first );
    std::cout << "Route: " << pref.toString() << "/" << pref.getNetworkPrefixLength() << " -> ";
		mux_t mux = it->second;
    std::cout << mux << std::endl;
    gRoutingTable.clear();
	}
}

int main(int argc, char* argv[])
{
  int ret = 0;

	ConnectionList cl;
  std::stringstream iss_;
  int32_t missing_chars=-1;
  int32_t buffer_size_=0;
  while( std::cin.good() )
  {
    char c;
    std::cin.get(c);
    iss_ << c;
    buffer_size_++;
    while (1)
    {
      if(missing_chars==-1 && buffer_size_>5)
      {
        char * buffer = new char [6+1];
        iss_.read(buffer,6);
        std::stringstream tmp;
        tmp.write(buffer,6);
        tmp>>missing_chars;
        delete[] buffer;
        buffer_size_-=6;
      } 
      else if( missing_chars>0 && missing_chars<=buffer_size_ )
      {
        char * buffer = new char [missing_chars+1];
        iss_.read(buffer,missing_chars);
        std::stringstream tmp;
        tmp.write(buffer,missing_chars);
        boost::archive::text_iarchive ia(tmp);
        SyncCommand scom(cl);
        ia >> scom;
        buffer_size_-=missing_chars;
        missing_chars=-1;
        output(cl);
        delete[] buffer;
      } 
      else
        break;
    }
  }
  return ret;
}

