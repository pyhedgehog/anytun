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

  Buffer test(25);
  for(unsigned int i=0; i<test.getLength(); ++i)
    test[i] = i+1;
  Package pack(test);

  std::cout << std::hex;

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasHeader() << " seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << std::endl;

//   pack.setSeqNr(0x55AA55AA).setSenderId(0xBB11);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasHeader() << " seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << std::endl;
  
//   pack.addHeader(0x12345678, 0x9ABC);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasHeader() << " seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << std::endl;

//   pack.removeHeader();

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasHeader() << " seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << std::endl;

//   pack.withHeader(true);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasHeader() << " seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << std::endl;

//   pack.withHeader(false);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: hdr=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;
  
//   pack.addPayloadType(0xCCFF);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: payt=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;
  
//   pack.addPayloadType(0xEEBB);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: payt=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;

//   pack.removePayloadType();

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: payt=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;

//   pack.withPayloadType(true);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: payt=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;

//   pack.withPayloadType(false);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: payt=" << pack.hasPayloadType() << " payload_type=" << pack.getPayloadType() << std::endl;

//   pack.addAuthTag(0xCCDDEEFF);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: autht=" << pack.hasAuthTag() << " auth_tag=" << pack.getAuthTag() << std::endl;

//   pack.removeAuthTag();

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: autht=" << pack.hasAuthTag() << " auth_tag=" << pack.getAuthTag() << std::endl;

//   pack.withAuthTag(true);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: autht=" << pack.hasAuthTag() << " auth_tag=" << pack.getAuthTag() << std::endl;

//   pack.withAuthTag(false);

//   std::cout << "pack[0-" << pack.getLength() << "]: '";
//   for(unsigned int i=0; i<pack.getLength(); ++i)
//     std::cout << (int)pack[i] << ",";
//   std::cout << std::endl;
//   std::cout << "pack: autht=" << pack.hasAuthTag() << " auth_tag=" << pack.getAuthTag() << std::endl;
  
  std::cout << std::endl << std::endl;

  pack.addHeader(0x56789ABC,0xDEF0);

  std::cout << "pack[0-" << pack.getLength() << "]: '";
  for(unsigned int i=0; i<pack.getLength(); ++i)
    std::cout << (int)pack[i] << ",";
  std::cout << std::endl;
  std::cout << "pack: hdr=" << pack.hasHeader() << " payt=" << pack.hasPayloadType() << " autht=" << pack.hasAuthTag() << std::endl;
  std::cout << "seq_nr=" << pack.getSeqNr() << " sender_id=" << pack.getSenderId() << " payload_type=" << pack.getPayloadType()
            << " auth_tag=" << pack.getAuthTag() << std::endl;

  std::cout << std::dec;

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
