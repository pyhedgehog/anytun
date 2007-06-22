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
#include "buffer.h"
#include "packet.h"
#include "cypher.h"
#include "authAlgo.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0800

struct Param
{
  Options& opt;
  TunDevice& dev;
  Cypher& c;
  AuthAlgo& a;
  PacketSource& src;
  SeqWindow& seq;
};

void* sender(void* p)
{
  Param* param = reinterpret_cast<Param*>(p);

  seq_nr_t seq = 0;
  while(1)
  {
    Packet pack(1600);

        // read packet from device
    int len = param->dev.read(pack);
    pack.resizeBack(len);

    if(param->opt.getRemoteAddr() == "")
      continue;

        // add payload type
    if(param->dev.getType() == TunDevice::TYPE_TUN)
      pack.addPayloadType(PAYLOAD_TYPE_TUN);
    else if(param->dev.getType() == TunDevice::TYPE_TAP)
      pack.addPayloadType(PAYLOAD_TYPE_TAP);
    else 
      pack.addPayloadType(0);

        // cypher the packet
    param->c.cypher(pack);

        // add header to packet
    pack.addHeader(param->opt.getSenderId(), seq);

        // calc auth_tag and add it to the packet
    auth_tag_t at = param->a.calc(pack);
    pack.addAuthTag(at);

        // send it out to remote host
    param->src.send(pack, param->opt.getRemoteAddr(), param->opt.getRemotePort());
  }
  pthread_exit(NULL);
}

void* receiver(void* p)
{
  Param* param = reinterpret_cast<Param*>(p);  
  
  while(1)
  {
    string remote_host;
    u_int16_t remote_port;
    Packet pack(1600);
        // read packet from socket
    u_int32_t len = param->src.recv(pack, remote_host, remote_port);
    pack.resizeBack(len);
    pack.withPayloadType(true).withHeader(true).withAuthTag(true);

        // check auth_tag and remove it
    auth_tag_t at = pack.getAuthTag();
    pack.removeAuthTag();
    if(at != param->a.calc(pack))
      continue;

        // autodetect peer
    if(param->opt.getRemoteAddr() == "")
    {
      param->opt.setRemoteAddrPort(remote_host, remote_port);
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_host << ":" << remote_port;
    }
        // compare sender_id and seq with window
    if(param->seq.hasSeqNr(pack.getSenderId(), pack.getSeqNr()))
      continue;
    param->seq.addSeqNr(pack.getSenderId(), pack.getSeqNr());
    pack.removeHeader();

        // decypher the packet
    param->c.cypher(pack);
    
        // check payload_type and remove it
    if((param->dev.getType() == TunDevice::TYPE_TUN && pack.getPayloadType() != PAYLOAD_TYPE_TUN) ||
       (param->dev.getType() == TunDevice::TYPE_TAP && pack.getPayloadType() != PAYLOAD_TYPE_TAP))
      continue;
    pack.removePayloadType();
    
        // write it on the device
    param->dev.write(pack);
  }
  pthread_exit(NULL);
}

int main(int argc, char* argv[])
{
  std::cout << "anytun - secure anycast tunneling protocol" << std::endl;
  Options opt;
  if(!opt.parse(argc, argv))
  {
    opt.printUsage();
    exit(-1);
  }
  cLog.msg(Log::PRIO_NOTICE) << "anytun started...";

  SignalController sig;
  sig.init();
  
  TunDevice dev(opt.getDevName().c_str(), opt.getIfconfigParamLocal().c_str(), opt.getIfconfigParamRemoteNetmask().c_str());
  SeqWindow seq(opt.getSeqWindowSize());
  NullCypher c;
  NullAuthAlgo a;
  PacketSource* src;
  if(opt.getLocalAddr() == "")
    src = new UDPPacketSource(opt.getLocalPort());
  else
    src = new UDPPacketSource(opt.getLocalAddr(), opt.getLocalPort());

  struct Param p = {opt, dev, c, a, *src, seq};
    
  std::cout << "dev created (opened)" << std::endl;
  std::cout << "dev opened - actual name is '" << p.dev.getActualName() << "'" << std::endl;
  std::cout << "dev type is '" << p.dev.getTypeString() << "'" << std::endl;
  
  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, &p);  
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &p);  

  int ret = sig.run();

  pthread_cancel(senderThread);
  pthread_cancel(receiverThread);  
  pthread_join(senderThread, NULL);
  pthread_join(receiverThread, NULL);

  delete src;

  return ret;
}
