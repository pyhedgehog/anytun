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

#define STR_ERROR "\x1b[31;1mError: "
#define STR_PASSED "\x1b[32;1mTest PASSED: "
#define STR_END "\x1b[0m\n"

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/assign.hpp>
#include <iostream>
#include <fstream>

#include "datatypes.h"

#include "log.h"
#include "resolver.h"
#include "buffer.h"
#include "plainPacket.h"
#include "encryptedPacket.h"
#include "cipher.h"
#include "keyDerivation.h"
#include "authAlgo.h"
#include "cipherFactory.h"
#include "authAlgoFactory.h"
#include "keyDerivationFactory.h"
#include "signalController.h"
#if !defined(_MSC_VER) && !defined(MINGW)
# include "daemonService.h"
#else
# ifdef WIN_SERVICE
#  include "win32/winService.h"
# else
#  include "nullDaemon.h"
# endif
#endif
#include "packetSource.h"
#include "tunDevice.h"
#include "options.h"
#include "seqWindow.h"
#include "connectionList.h"
#ifndef NO_ROUTING
#include "routingTable.h"
#include "networkAddress.h"
#endif

#ifndef ANYTUN_NOSYNC
#include "syncQueue.h"
#include "syncCommand.h"
#include "syncServer.h"
#include "syncClient.h"
#include "syncOnConnect.hpp"
#endif

#include "cryptinit.hpp"
#include "crypto/interface.h"
#include "crypto/openssl.h"
#include "sysExec.h"

char test_text[] = "Anytun is an implementation of the secure anycast tunneling protocol. It uses an easy openvpn style interface and makes it possible to build redundant VPN clusters with load balancing between servers. VPN servers share a single IP address. Adding and removing VPN Servers is done by the routing protocol, so no client changes have to be made when additional VPN servers are added or removed. It is possible to realise global load balancing based on shortest BGP routes by simply announcing the address space of the tunnel servers at multiple locations. Currently ethernet, ipv4 and ipv6 tunnels are supported by the implementation. However the protocol allows one to tunnel every ETHERTYPE protocol.";

void testCrypt()
{
    std::auto_ptr<Cipher> c(CipherFactory::create("aes-ctr", KD_OUTBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create("sha1", KD_OUTBOUND));
    KeyDerivation* kd = KeyDerivationFactory::create("aes-ctr");
    kd->init("", "", "abc" );
    kd->setRole(ROLE_LEFT);

    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, 20);

    uint16_t mux = 1;
    plain_packet.setLength(MAX_PACKET_LENGTH);

    memcpy(plain_packet.getPayload(),test_text,sizeof(test_text));

    // read packet from device
    int len = sizeof(test_text);

    plain_packet.setPayloadLength(len);
    // set payload type
    plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
    //write(0, plain_packet.getPayload(), plain_packet.getLength());

    // encrypt packet
    c->encrypt(*kd, plain_packet, encrypted_packet, 1, 1, mux);

    encrypted_packet.setHeader(1, 1, mux);

    // add authentication tag
    a->generate(*kd, encrypted_packet);
    Buffer tag0( encrypted_packet.getAuthTag(), encrypted_packet.getAuthTagLength(), false);
    std::cout << "Tag 0:" << tag0.getHexDump() << std::endl;
    std::auto_ptr<crypto::Interface> cnew(new crypto::Openssl());
    Buffer masterkey(uint32_t(crypto::DEFAULT_KEY_LENGTH/8) , false);
    Buffer mastersalt(crypto::SALT_LENGTH, false);
    cnew->calcMasterKeySalt("abc", uint32_t(crypto::DEFAULT_KEY_LENGTH/8), masterkey , mastersalt);
    if(!cnew->checkAndRemoveAuthTag(encrypted_packet, masterkey, mastersalt, ROLE_RIGHT )) {
      std::cout << STR_ERROR << "wrong Authentication Tag!" << STR_END;
      //exit(-1);
    }

    encrypted_packet.withAuthTag(false);
    memset(plain_packet.getPayload(),0,MAX_PACKET_LENGTH);
    kd->setRole(ROLE_RIGHT);

    c->decrypt(*kd, encrypted_packet, plain_packet);
//    std::cout << "Master Key:" << kd->master_key_.getHexDump() << std::endl;
//    std::cout << "Master Salt:" << kd->master_salt_.getHexDump() << std::endl;

    if (!memcmp(plain_packet.getPayload(), test_text, sizeof(test_text))) {
      std::cerr << "role test error" << std::endl;
      exit(-1);
    }
    std::cout << STR_PASSED << "role RIGHT and role LEFT are different"<< STR_END;

    c = std::auto_ptr<Cipher>(CipherFactory::create("aes-ctr", KD_INBOUND));
    a = std::auto_ptr<AuthAlgo>(AuthAlgoFactory::create("sha1", KD_INBOUND));

    // check whether auth tag is ok or not
//    Buffer tag1( encrypted_packet.getAuthTag(), encrypted_packet.getAuthTagLength(), false);
//    std::cout << "Tag 1:" << tag1.getHexDump() << std::endl;


    c->decrypt(*kd, encrypted_packet, plain_packet);
    if (memcmp(plain_packet.getPayload(), test_text, sizeof(test_text))) {
      std::cerr << "crypto test failed" << std::endl;
      std::cout << test_text << std::endl;
      ssize_t len = write(0, plain_packet.getPayload(), plain_packet.getLength());
      if (len)
        len++; // fix unused varable
      exit(-1);
    }
    std::cout << STR_PASSED << "role RIGHT inbound can decrypt role LEFT's outbound packets"<< STR_END;

    memset(plain_packet.getPayload(), 0, sizeof(test_text));
    std::cout << "Master Key:" << masterkey.getHexDump() << std::endl;
    std::cout << "Master Salt:" << mastersalt.getHexDump() << std::endl;
    cnew->addAuthTag(encrypted_packet, masterkey, mastersalt, ROLE_LEFT );
    Buffer tag2( encrypted_packet.getAuthTag(), encrypted_packet.getAuthTagLength(), false);
    std::cout << "Tag 2:" << tag2.getHexDump() << std::endl;
    if(!a->checkTag(*kd, encrypted_packet)) {
      std::cout << STR_ERROR << "wrong Authentication Tag!" << STR_END;
      //exit(-1);
    }
    cnew->decrypt(encrypted_packet, plain_packet, masterkey, mastersalt, ROLE_RIGHT );
    if (memcmp(plain_packet.getPayload(), test_text, sizeof(test_text))) {
      std::cerr << "crypto test failed" << std::endl;
      std::cout << test_text << std::endl;
      ssize_t len = write(0, plain_packet.getPayload(), plain_packet.getLength());
      if (len)
        len++; // fix unused varable
      exit(-1);
    }
    std::cout << STR_PASSED << "new role RIGHT inbound can decrypt old role LEFT's outbound packets"<< STR_END;
}

void newCrypt()
{
  std::auto_ptr<crypto::Interface> cnew(new crypto::Openssl());
  Buffer masterkey(uint32_t(crypto::DEFAULT_KEY_LENGTH/8) , false);
  Buffer mastersalt(crypto::SALT_LENGTH, false);
  cnew->calcMasterKeySalt("abc", uint32_t(crypto::DEFAULT_KEY_LENGTH/8), masterkey , mastersalt);
  PlainPacket plain_packet(MAX_PACKET_LENGTH);
  EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, 20);
  for(uint32_t seq=0; seq < 1000000; seq++) {

    memset(encrypted_packet.getPayload(), 0, MAX_PACKET_LENGTH);
    uint16_t mux = 1;
    plain_packet.setLength(MAX_PACKET_LENGTH);

    memcpy(plain_packet.getPayload(),test_text,sizeof(test_text));

    // read packet from device
    int len = sizeof(test_text);

    plain_packet.setPayloadLength(len);
    // set payload type
    plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
    //write(0, plain_packet.getPayload(), plain_packet.getLength());

    cnew->encrypt(plain_packet, encrypted_packet, masterkey, mastersalt, ROLE_LEFT, seq, 1, mux);

    cnew->addAuthTag(encrypted_packet, masterkey, mastersalt, ROLE_LEFT );

    memset(plain_packet.getPayload(), 0, sizeof(test_text));

    if(!cnew->checkAndRemoveAuthTag(encrypted_packet, masterkey, mastersalt, ROLE_RIGHT )) {
      std::cout << STR_ERROR << "wrong Authentication Tag!" << STR_END;
      //exit(-1);
    }

    cnew->decrypt(encrypted_packet, plain_packet, masterkey, mastersalt, ROLE_RIGHT );
    if (memcmp(plain_packet.getPayload(), test_text, sizeof(test_text))) {
      std::cerr << "crypto test failed" << std::endl;
      std::cout << test_text << std::endl;
      ssize_t len = write(0, plain_packet.getPayload(), plain_packet.getLength());
      if (len)
        len++; // fix unused varable
      exit(-1);
    }
  }
}

void oldCrypt()
{
    std::auto_ptr<Cipher> c(CipherFactory::create("aes-ctr", KD_OUTBOUND));
    std::auto_ptr<AuthAlgo> a(AuthAlgoFactory::create("sha1", KD_OUTBOUND));
    KeyDerivation* kd = KeyDerivationFactory::create("aes-ctr");
    kd->init("", "", "abc" );
    kd->setRole(ROLE_LEFT);

    PlainPacket plain_packet(MAX_PACKET_LENGTH);
    EncryptedPacket encrypted_packet(MAX_PACKET_LENGTH, 20);
    for(uint32_t seq=0; seq < 1000000; seq++) {
      memset(encrypted_packet.getPayload(), 0, MAX_PACKET_LENGTH);
      uint16_t mux = 1;
      plain_packet.setLength(MAX_PACKET_LENGTH);

      memcpy(plain_packet.getPayload(),test_text,sizeof(test_text));

      // read packet from device
      int len = sizeof(test_text);

      plain_packet.setPayloadLength(len);
      // set payload type
      plain_packet.setPayloadType(PAYLOAD_TYPE_TUN);
      //write(0, plain_packet.getPayload(), plain_packet.getLength());

      // encrypt packet
      c->encrypt(*kd, plain_packet, encrypted_packet, seq, 1, mux);

      encrypted_packet.setHeader(seq, 1, mux);

      // add authentication tag
      a->generate(*kd, encrypted_packet);

      memset(plain_packet.getPayload(),0,MAX_PACKET_LENGTH);

      if(!a->checkTag(*kd, encrypted_packet)) {
        std::cout << STR_ERROR << "wrong Authentication Tag!" << STR_END;
        //exit(-1);
      }

      c->decrypt(*kd, encrypted_packet, plain_packet);
  //    std::cout << "Master Key:" << kd->master_key_.getHexDump() << std::endl;
  //    std::cout << "Master Salt:" << kd->master_salt_.getHexDump() << std::endl;
      if (memcmp(plain_packet.getPayload(), test_text, sizeof(test_text))) {
        std::cerr << "test error" << std::endl;
        exit(-1);
      }
   }
}

int main(int argc, char* argv[])
{ 
  cLog.addTarget("stdout:5");
  try {
    testCrypt();
    std::cout << "oldCrypt" << std::endl;
    clock_t begin_time = clock();
    // do something
    oldCrypt();
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << std::endl;
    std::cout << "newCrypt" << std::endl;
    begin_time = clock();
    newCrypt();
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << std::endl;
  } catch (std::exception& e) {
    std::cerr << e.what();
    return 1;
  }
  std::cout << "all tests passed" << std::endl;
  return 0;
}


