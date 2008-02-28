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

#include <gcrypt.h>
#include <cerrno>     // for ENOMEM

#include "datatypes.h"

#include "log.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cipher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "authTag.h"
#include "cipherFactory.h"
#include "authAlgoFactory.h"
#include "keyDerivationFactory.h"
#include "signalController.h"
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"
#include "routingTable.h"
#include "networkAddress.h"

#include "syncQueue.h"
#include "syncSocketHandler.h"
#include "syncListenSocket.h"

#include "syncSocket.h"
#include "syncClientSocket.h"
#include "syncCommand.h"

#include "threadParam.h"

#define MAX_PACKET_LENGTH 1600

#define SESSION_KEYLEN_AUTH 20   // TODO: hardcoded size
#define SESSION_KEYLEN_ENCR 16   // TODO: hardcoded size
#define SESSION_KEYLEN_SALT 14   // TODO: hardcoded size

void createConnection(const std::string & remote_host, u_int16_t remote_port, ConnectionList & cl, u_int16_t seqSize, SyncQueue & queue, mux_t mux)
{
  SeqWindow * seq= new SeqWindow(seqSize);
  seq_nr_t seq_nr_=0;
  KeyDerivation * kd = KeyDerivationFactory::create(gOpt.getKdPrf());
  kd->init(gOpt.getKey(), gOpt.getSalt());
  cLog.msg(Log::PRIO_NOTICE) << "added connection remote host " << remote_host << ":" << remote_port;
  ConnectionParam connparam ( (*kd),  (*seq), seq_nr_, remote_host,  remote_port);
  cl.addConnection(connparam,mux);
  NetworkAddress addr(ipv4,gOpt.getIfconfigParamRemoteNetmask().c_str());
  NetworkPrefix prefix(addr);
  gRoutingTable.addRoute(prefix,mux);
  std::ostringstream sout;
  boost::archive::text_oarchive oa(sout);
  const SyncCommand scom(cl,mux);
  const SyncCommand scom2 (prefix);
  oa << scom;
  std::cout <<  std::setw(5) << std::setfill('0') << sout.str().size()<< ' ' << sout.str() << std::endl;
	std::ostringstream sout2;
	boost::archive::text_oarchive oa2(sout2);
  oa2 << scom2;
  std::cout <<  std::setw(5) << std::setfill('0') << sout2.str().size()<< ' ' << sout2.str() << std::endl;
}

int main(int argc, char* argv[])
{
  int ret=0;
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }

  SignalController sig;
  sig.init();

	ConnectionList cl;
	SyncQueue queue;

	if(gOpt.getRemoteAddr() != "")
	{
		createConnection(gOpt.getRemoteAddr(),gOpt.getRemotePort(),cl,gOpt.getSeqWindowSize(), queue, gOpt.getMux());

	}

  return ret;
}

