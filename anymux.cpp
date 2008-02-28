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

#include <iostream>
#include <fstream>
#include <poll.h>

#include "datatypes.h"

#include "log.h"
#include "signalController.h"
#include "anymuxOptions.h"

#include "muxSocket.h"
#include "Sockets/ListenSocket.h"
#include "Sockets/SocketHandler.h"


class ThreadParam
{
public:
  ThreadParam() : port(0) {};
  u_int16_t port;
};


void* syncListener(void* p )
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);
	SOCKETS_NAMESPACE::SocketHandler h;
	SOCKETS_NAMESPACE::ListenSocket<MuxSocket> l(h,true);

	if( l.Bind(param->port) )
		pthread_exit(NULL);

	Utility::ResolveLocal(); // resolve local hostname
	h.Add(&l);
	h.Select(1,0);
	while (1) {
		h.Select(1,0);
	}
}
int main(int argc, char* argv[])
{
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }
  
  std::ifstream file( gOpt.getFileName().c_str() );
  if( file.is_open() )
    file.close();
  else
  {
    std::cout << "ERROR: unable to open file!" << std::endl;
    exit(-1);
  }

  SignalController sig;
  sig.init();

  ThreadParam p;
  p.port = gOpt.getLocalPort(); 
	pthread_t syncListenerThread;
	pthread_create(&syncListenerThread, NULL, syncListener, &p);  

	int ret = sig.run();

	pthread_cancel(syncListenerThread);  
  
	pthread_join(syncListenerThread, NULL);

  return ret;
}

