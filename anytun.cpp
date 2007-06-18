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
#include <poll.h>

#include "datatypes.h"

#include "tunDevice.h"
#include "buffer.h"
#include "package.h"
#include "cypher.h"
#include "authAlgo.h"

int main(int argc, char* argv[])
{
  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;

//   TunDevice* dev;
//   dev = new TunDevice("tun", "192.168.200.1", "192.168.201.1");
//   std::cout << "dev created (opened)" << std::endl;
//   std::cout << "dev opened - actual name is '" << dev->getActualName() << "'" << std::endl;
//   std::cout << "dev type is '" << dev->getType() << "'" << std::endl;
  
//   sleep(10);
  
//   Buffer inBuf(2000);
  
//   while(1)
//   {
//     short revents = dev->read(inBuf);
//     if(revents & POLLIN)
//       std::cout << "POLLIN,";
//     else if(revents & POLLRDNORM)
//       std::cout << "POLLRDNORM,";
//     else if(revents & POLLRDBAND)
//       std::cout << "POLLRDBAND,";
//     else if(revents & POLLPRI)
//       std::cout << "POLLPRI,";
//     else if(revents & POLLOUT)
//       std::cout << "POLLOUT,";
//     else if(revents & POLLWRNORM)
//       std::cout << "POLLWRNORM,";
//     else if(revents & POLLWRBAND)
//       std::cout << "POLLWRBAND,";
//     else if(revents & POLLERR)
//       std::cout << "POLLERR,";
//     else if(revents & POLLHUP)
//       std::cout << "POLLHUP,";
//     else if(revents & POLLNVAL)
//       std::cout << "POLLNVAL,";
//     std::cout << std::endl;
//   }

//   delete dev;
//   std::cout << "dev destroyed" << std::endl;

//   dev = new TunDevice("tap", "192.168.202.1", "255.255.255.0");
//   std::cout << "dev created (opened)" << std::endl;
//   std::cout << "dev opened - actual name is '" << dev->getActualName() << "'" << std::endl;
//   std::cout << "dev type is '" << dev->getType() << "'" << std::endl;
//   sleep(10);
//   delete dev;
//   std::cout << "dev destroyed" << std::endl;

//   sleep(10);

//   dev = new TunDevice("tun17", "192.168.200.1", "192.168.201.1");
//   std::cout << "dev created (opened)" << std::endl;
//   std::cout << "dev opened - actual name is '" << dev->getActualName() << "'" << std::endl;
//   std::cout << "dev type is '" << dev->getType() << "'" << std::endl;
//   sleep(10);
//   delete dev;
//   std::cout << "dev destroyed" << std::endl;


  return 0;
}
