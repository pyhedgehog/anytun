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
#include "keyDerivation.h"
#include "authAlgo.h"
//#include "authTag.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0800

struct Param
{
  Options& opt;
  TunDevice& dev;
  PacketSource& src;
	ConnectionList& cl;
};

void createConnection(const std::string & remote_host , u_int16_t remote_port, ConnectionList & cl, u_int16_t seqSize)
{

	SeqWindow seq(seqSize);

  uint8_t key[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't'
  };

  uint8_t salt[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n'
  };


  KeyDerivation kd;
  //kd.init(Buffer(key, sizeof(key)), Buffer(salt, sizeof(salt)));
  std::cout << "anytun.cpp: crateConnection called" << std::endl;
	ConnectionParam connparam ( kd,  seq, remote_host,  remote_port);
	cl.addConnection(connparam,std::string("default"));
}

void* sender(void* p)
{
  Param* param = reinterpret_cast<Param*>(p);
	//TODO make Cypher selectable with command line option
	NullCypher c;
//  AesIcmCypher c;
//  NullAuthAlgo a;

  seq_nr_t seq = 0;
  while(1)
  {
    Packet pack(1600); // fix me... mtu size

    // read packet from device
    int len = param->dev.read(pack);
    pack.resizeBack(len);

    if( param->cl.empty())
      continue;
		ConnectionParam conn = param->cl.getConnection();
    // add payload type
    if(param->dev.getType() == TunDevice::TYPE_TUN)
      pack.addPayloadType(PAYLOAD_TYPE_TUN);
    else if(param->dev.getType() == TunDevice::TYPE_TAP)
      pack.addPayloadType(PAYLOAD_TYPE_TAP);
    else 
      pack.addPayloadType(0);

    // cypher the packet
    Buffer tmp_key(16), tmp_salt(14);
		//TODO fix key derivation!
    //conn.kd_.generate(label_satp_encryption, seq, tmp_key, tmp_key.getLength());
    //conn.kd_.generate(label_satp_salt, seq, tmp_salt, tmp_salt.getLength());
    c.setKey(tmp_key);
    c.setSalt(tmp_salt);

    //std::cout << "Send Package: seq: " << seq << std::endl << "sID: " <<  param->opt.getSenderId() << std::endl;
    //std::cout << "Package dump: " << pack.getBuf() << std::endl;

    c.cypher(pack, seq, param->opt.getSenderId());

    // add header to packet
    pack.addHeader(seq, param->opt.getSenderId());
    seq++;

//    // calc auth_tag and add it to the packet
//    AuthTag at = a.calc(pack);
//    if(at != AuthTag(0)) {
//      //auth_tag_t at = a.calc(pack);
//      pack.addAuthTag(at);
//    }
//
    // send it out to remote host
    param->src.send(pack, param->opt.getRemoteAddr(), param->opt.getRemotePort());
  }
  pthread_exit(NULL);
}

void* sync_receiver(void* p)
{
	Param* param = reinterpret_cast<Param*>(p);

	while(1)
	{
	}
}

void* receiver(void* p)
{
  Param* param = reinterpret_cast<Param*>(p);  
  NullCypher c;
//  AesIcmCypher c;
//  NullAuthAlgo a;
  
  while(1)
  {
    string remote_host;
    u_int16_t remote_port;
    u_int16_t sid = 0, seq = 0;
    Packet pack(1600);  // fix me... mtu size

    // read packet from socket
    u_int32_t len = param->src.recv(pack, remote_host, remote_port);
    pack.resizeBack(len);
//    pack.withPayloadType(true).withHeader(true).withAuthTag(true);
    pack.withPayloadType(true).withHeader(true).withAuthTag(false);

//    // check auth_tag and remove it
//    AuthTag at = pack.getAuthTag();
//    pack.removeAuthTag();
//    if(at != a.calc(pack))
//      continue;

    // autodetect peer
		// TODO fixme, IP might change!!!
    if(param->opt.getRemoteAddr() == "" && param->cl.empty())
		{
			createConnection(remote_host, remote_port, param->cl,param->opt.getSeqWindowSize());
      cLog.msg(Log::PRIO_NOTICE) << "autodetected remote host " << remote_host << ":" << remote_port;
		}
		ConnectionParam conn = param->cl.getConnection();

    sid = pack.getSenderId();
    seq = pack.getSeqNr();
    // compare sender_id and seq with window
    if(conn.seq_.hasSeqNr(pack.getSenderId(), pack.getSeqNr()))
      continue;
    conn.seq_.addSeqNr(pack.getSenderId(), pack.getSeqNr());
    pack.removeHeader();

    // decypher the packet
    Buffer tmp_key(16), tmp_salt(14);
    //conn.kd_.generate(label_satp_encryption, seq, tmp_key, tmp_key.getLength());
    //conn.kd_.generate(label_satp_salt, seq, tmp_salt, tmp_salt.getLength());
    c.setKey(tmp_key);
    c.setSalt(tmp_salt);
    c.cypher(pack, seq, sid);
   
    //std::cout << "Received Package: seq: " << seq << std::endl << "sID: " << sid << std::endl;
    //std::cout << "Package dump: " << pack.getBuf() << std::endl;

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
  std::string dev_type(opt.getDevType()); 
  TunDevice dev(opt.getDevName().c_str(), dev_type=="" ? NULL : dev_type.c_str(), opt.getIfconfigParamLocal().c_str(), opt.getIfconfigParamRemoteNetmask().c_str());

  PacketSource* src;
  if(opt.getLocalAddr() == "")
    src = new UDPPacketSource(opt.getLocalPort());
  else
    src = new UDPPacketSource(opt.getLocalAddr(), opt.getLocalPort());

	ConnectionList cl;

	if(opt.getRemoteAddr() != "")
		createConnection(opt.getRemoteAddr(),opt.getRemotePort(),cl,opt.getSeqWindowSize());

  struct Param p = {opt, dev, *src, cl};
    
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

