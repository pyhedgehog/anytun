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

#ifndef ANYTUN_crypto_interface_h_INCLUDED
#define ANYTUN_crypto_interface_h_INCLUDED

#include "../datatypes.h"
#include "../options.h"
#include "../buffer.h"
#include "../plainPacket.h"
#include "../encryptedPacket.h"

#define LABEL_ENC 0
#define LABEL_AUTH 1
#define LABEL_SALT 2

#define LABEL_LEFT_ENC 0x356A192B
#define LABEL_RIGHT_ENC 0xDA4B9237
#define LABEL_LEFT_SALT 0x77DE68DA
#define LABEL_RIGHT_SALT 0x1B645389
#define LABEL_LEFT_AUTH 0xAC3478D6
#define LABEL_RIGHT_AUTH 0xC1DFD96E

namespace crypto {

  typedef enum { KD_INBOUND, KD_OUTBOUND } kd_dir_t;

  class Interface
  {
  public:
    virtual ~Interface() {};
    // pure virtual
    virtual void init(Buffer key, Buffer salt, std::string passphrase = "") = 0;
    virtual bool generatePacketKey( kd_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, const Buffer& masterkey , const Buffer& mastersalt, Buffer& key) = 0;
    virtual void calcMasterKey(std::string passphrase, uint16_t length, Buffer& masterkey ) = 0;
    virtual void calcMasterSalt(std::string passphrase, uint16_t length, Buffer& mastersalt ) = 0;
    virtual void encrypt(const Buffer& key, PlainPacket& in, EncryptedPacket& out) = 0;
    virtual void decrypt(const Buffer& key, EncryptedPacket& in, PlainPacket& out) = 0;
    // virtual
    virtual std::string printType();
    //static
    static satp_prf_label_t convertLabel(kd_dir_t dir,  role_t role, satp_prf_label_t label);
    static bool init();
  };
};

#endif
