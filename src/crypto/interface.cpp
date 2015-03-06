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

#include "interface.h"
#include "../log.h"
#include "../endian.h"

namespace crypto {

Interface::~Interface()
{
}

void Interface::encrypt(PlainPacket& in, EncryptedPacket& out, const Buffer& masterkey, const Buffer& mastersalt, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  uint32_t len = cipher(in.getPayload(), in.getLength(), out.getPayload(), out.getPayloadLength(), masterkey, mastersalt, role, seq_nr, sender_id, mux);
  out.setSenderId(sender_id);
  out.setSeqNr(seq_nr);
  out.setMux(mux);
  out.setPayloadLength(len);
}

void Interface::decrypt(EncryptedPacket& in, PlainPacket& out, const Buffer& masterkey, const Buffer& mastersalt, role_t role)
{
  uint32_t len = decipher(in.getPayload() , in.getPayloadLength(), out.getPayload(), out.getLength(), masterkey, mastersalt, role, in.getSeqNr(), in.getSenderId(), in.getMux());
  out.setLength(len);
}

bool Interface::checkAndRemoveAuthTag(EncryptedPacket& packet, const Buffer& masterkey, const Buffer& mastersalt, role_t role)
{
  uint32_t digest_length = getDigestLength();
  packet.withAuthTag(true);
  if(!packet.getAuthTagLength()) {
    return true;
  }

  Buffer digest(digest_length);
  //Buffer key(masterkey.getLength(), false);
  Buffer key(digest_length, false);
  deriveKey(KD_INBOUND, LABEL_AUTH, role, packet.getSeqNr(), packet.getSeqNr(), packet.getMux(), masterkey, mastersalt, key);
  //std::cout << "Interface::checkAndRemoveAuthTag: " << key.getHexDump() << std::endl;
  calcAuthKey(key, digest,  packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength() );

  uint8_t* tag = packet.getAuthTag();
  uint32_t length = (packet.getAuthTagLength() < digest_length) ? packet.getAuthTagLength() : digest_length;

  if(length > digest_length)
    for(uint32_t i=0; i < (packet.getAuthTagLength() - digest_length); ++i)
      if(tag[i]) { return false; }

  int ret = std::memcmp(&tag[packet.getAuthTagLength() - length], digest.getBuf() + digest_length - length, length);
  packet.removeAuthTag();

  if(ret) {
    return false;
  }

  return true;
}

void Interface::addAuthTag(EncryptedPacket& packet, const Buffer& masterkey, const Buffer& mastersalt, role_t role)
{
  uint32_t digest_length = getDigestLength();
  packet.addAuthTag();
  if(!packet.getAuthTagLength()) {
    return;
  }
  Buffer digest(digest_length);
  //Buffer key(masterkey.getLength(), false);
  Buffer key(digest_length, false);
  deriveKey(KD_OUTBOUND, LABEL_AUTH, role, packet.getSeqNr(), packet.getSeqNr(), packet.getMux(), masterkey, mastersalt, key);
  //std::cout << "Interface::addAuthTag: " << key.getHexDump() << std::endl;
  calcAuthKey(key, digest,  packet.getAuthenticatedPortion(), packet.getAuthenticatedPortionLength() );
  uint8_t* tag = packet.getAuthTag();
  uint32_t length = (packet.getAuthTagLength() < digest_length) ? packet.getAuthTagLength() : digest_length;

  if(length > digest_length) {
    std::memset(tag, 0, packet.getAuthTagLength());
  }

  std::memcpy(&tag[packet.getAuthTagLength() - length], digest.getBuf() + digest_length - length, length);

}

satp_prf_label_t Interface::convertLabel(kd_dir_t dir, role_t role, satp_prf_label_t label)
{
  switch(label) {
  case LABEL_ENC: {
    if(dir == KD_OUTBOUND) {
      if(role == ROLE_LEFT) { return LABEL_LEFT_ENC; }
      if(role == ROLE_RIGHT) { return LABEL_RIGHT_ENC; }
    } else {
      if(role == ROLE_LEFT) { return LABEL_RIGHT_ENC; }
      if(role == ROLE_RIGHT) { return LABEL_LEFT_ENC; }
    }
    break;
  }
  case LABEL_SALT: {
    if(dir == KD_OUTBOUND) {
      if(role == ROLE_LEFT) { return LABEL_LEFT_SALT; }
      if(role == ROLE_RIGHT) { return LABEL_RIGHT_SALT; }
    } else {
      if(role == ROLE_LEFT) { return LABEL_RIGHT_SALT; }
      if(role == ROLE_RIGHT) { return LABEL_LEFT_SALT; }
    }
    break;
  }
  case LABEL_AUTH: {
    if(dir == KD_OUTBOUND) {
      if(role == ROLE_LEFT) { return LABEL_LEFT_AUTH; }
      if(role == ROLE_RIGHT) { return LABEL_RIGHT_AUTH; }
    } else {
      if(role == ROLE_LEFT) { return LABEL_RIGHT_AUTH; }
      if(role == ROLE_RIGHT) { return LABEL_LEFT_AUTH; }
    }
    break;
  }
  }

  return label;
}

std::string Interface::printType()
{
  return ""; 
}

bool Interface::init()
{
  return true;
};

void Interface::calcCryptCtr(const Buffer& masterkey, const Buffer& mastersalt, kd_dir_t dir, role_t role, satp_prf_label_t label, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux, cipher_aesctr_ctr_t * ctr)
{
  Buffer salt( (uint32_t) SALT_LENGTH, false);
  deriveKey(dir, LABEL_SALT, role, seq_nr, sender_id, mux, masterkey, mastersalt, salt);
  std::memcpy(ctr->salt_.buf_, salt.getConstBuf(), SALT_LENGTH);
  ctr->salt_.zero_ = 0;
  ctr->params_.mux_ ^= MUX_T_HTON(mux);
  ctr->params_.sender_id_ ^= SENDER_ID_T_HTON(sender_id);
  ctr->params_.seq_nr_ ^= SEQ_NR_T_HTON(seq_nr);

  return;
}

void Interface::calcKeyCtr(const Buffer& mastersalt, kd_dir_t dir, role_t role, satp_prf_label_t label, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux, key_derivation_aesctr_ctr_t * ctr)
{
  
  if(mastersalt.getLength() != SALT_LENGTH) {
    cLog.msg(Log::PRIO_ERROR) << "Interface::calcKeyCtr: salt lengths don't match";
    throw std::runtime_error ("Interface::calcKeyCtr: salt lengths don't match");
  }
  std::memcpy(ctr->salt_.buf_, mastersalt.getConstBuf(), SALT_LENGTH);
  ctr->salt_.zero_ = 0;
  ctr->params_.label_ ^= SATP_PRF_LABEL_T_HTON(convertLabel(dir, role, label));
  ctr->params_.seq_ ^= SEQ_NR_T_HTON(seq_nr);
}

}
