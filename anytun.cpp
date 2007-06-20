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

#include "log.h"
#include "tunDevice.h"
#include "buffer.h"
#include "package.h"
#include "cypher.h"
#include "authAlgo.h"
#include "signalController.h"

void* sender(void* d)
{
  TunDevice* dev = reinterpret_cast<TunDevice*>(d);  
  
  Buffer buf(1600);
  while(1)
  {
    int len = dev->read(buf);
    std::cout << "read " << len << " bytes" << std::endl;
  }
  pthread_exit(NULL);
}

void* receiver(void* d)
{
  TunDevice* dev = reinterpret_cast<TunDevice*>(d);  
  
  Buffer buf(1234);
  while(1)
  {
    sleep(1);
    dev->write(buf);
  }
  pthread_exit(NULL);
}

int main(int argc, char* argv[])
{
  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;
  cLog.msg(Log::PRIO_NOTICE) << "anytun started...";
  
  SignalController sig;
  sig.init();
  
//  TunDevice dev("tun", "192.168.200.1", "192.168.201.1");
  TunDevice dev("tap", "192.168.202.1", "255.255.255.0");
//  TunDevice dev("tun17", "192.168.200.1", "192.168.201.1");
  
  std::cout << "dev created (opened)" << std::endl;
  std::cout << "dev opened - actual name is '" << dev.getActualName() << "'" << std::endl;
  std::cout << "dev type is '" << dev.getType() << "'" << std::endl;
  
  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, &dev);  
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &dev);  

  int ret = sig.run();

  pthread_cancel(senderThread);
  pthread_cancel(receiverThread);  
  pthread_join(senderThread, NULL);
  pthread_join(receiverThread, NULL);

  return ret;
}
