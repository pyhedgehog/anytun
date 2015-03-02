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

#include "openssl.h"
#include "../log.h"
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "../anytunError.h"

namespace crypto {

Openssl::~Openssl()
{

}


void Openssl::calcMasterKeySalt(std::string passphrase, uint16_t length, Buffer& masterkey , Buffer& mastersalt)
{
  cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation: calculating master key from passphrase";
  if(!length) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: bad master key length";
    return;
  }

  if(length > SHA256_DIGEST_LENGTH) {
    cLog.msg(Log::PRIO_ERROR) << "KeyDerivation: master key too long for passphrase algorithm";
    return;
  }
  Buffer digest(uint32_t(SHA256_DIGEST_LENGTH));
  SHA256(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.length(), digest.getBuf());
  masterkey.setLength(length);

  std::memcpy(masterkey.getBuf(), &digest.getBuf()[digest.getLength() - masterkey.getLength()], masterkey.getLength());

  cLog.msg(Log::PRIO_NOTICE) << "KeyDerivation: calculating master salt from passphrase";

  Buffer digestsalt(uint32_t(SHA_DIGEST_LENGTH));
  SHA1(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.length(), digestsalt.getBuf());
  mastersalt.setLength(SALT_LENGTH);

  std::memcpy(mastersalt.getBuf(), &digestsalt.getBuf()[digestsalt.getLength() - mastersalt.getLength()], mastersalt.getLength());
}

uint32_t Openssl::cipher(uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, const Buffer& masterkey, const Buffer& mastersalt, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  Buffer key(masterkey.getLength(), false);
  cipher_aesctr_ctr_t ctr;
  calcCryptCtr(masterkey, mastersalt, KD_OUTBOUND, role, LABEL_ENC, seq_nr, sender_id, mux, &ctr);
  deriveKey(KD_OUTBOUND, LABEL_ENC, role, seq_nr, sender_id, mux, masterkey, mastersalt, key);
  calc(in, ilen, out, olen, key, &ctr);
  return ilen>olen ? ilen : olen;
}

uint32_t Openssl::decipher(uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, const Buffer& masterkey, const Buffer& mastersalt, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  Buffer key(masterkey.getLength(), false);
  cipher_aesctr_ctr_t ctr;
  calcCryptCtr(masterkey, mastersalt, KD_INBOUND, role, LABEL_ENC, seq_nr, sender_id, mux, &ctr);
  deriveKey(KD_INBOUND, LABEL_ENC, role, seq_nr, sender_id, mux, masterkey, mastersalt, key);
  calc(in, ilen, out, olen, key, &ctr);
  return ilen>olen ? ilen : olen;
}


void Openssl::calc(uint8_t* in, uint32_t ilen, uint8_t* out, uint32_t olen, const Buffer& key, cipher_aesctr_ctr_t * ctr)
{
//  std::cout << "Packet key:" << key.getHexDump() << std::endl;
  AES_KEY aes_key;
  int ret = AES_set_encrypt_key(key.getConstBuf(), key.getLength()*8, &aes_key);
  if(ret) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher ssl key (code: " << ret << ")";
    AnytunError::throwErr() << "AesIcmCipher: Failed to set cipher ssl key (code: " << ret << ")";
  }

  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    AnytunError::throwErr() << ("AesIcmCipher: Failed to set cipher CTR: size doesn't fit");
  }
  unsigned int num = 0;
  uint8_t ecount_buf[AES_BLOCK_SIZE];
  std::memset(ecount_buf, 0, AES_BLOCK_SIZE);
  AES_ctr128_encrypt(in, out, (ilen < olen) ? ilen : olen, &aes_key, ctr->buf_, ecount_buf, &num);
}

void Openssl::deriveKey(kd_dir_t dir, satp_prf_label_t label, role_t role, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux, const Buffer& masterkey, const Buffer& mastersalt, Buffer& key)
{
//  std::cout << "Openssl::deriveKey :" << dir << " " << label << " " << seq_nr << " " << masterkey.getHexDump() << mastersalt.getHexDump() << std::endl;

  uint8_t ecount_buf[AES_BLOCK_SIZE];
  AES_KEY aes_key;
  int ret = AES_set_encrypt_key(masterkey.getConstBuf(), masterkey.getLength()*8, &aes_key);
  if(ret) {
    cLog.msg(Log::PRIO_ERROR) << "Openssl::deriveKey: Failed to set ssl key (code: " << ret << ")";
    return;
  }

  key_derivation_aesctr_ctr_t ctr;
  calcKeyCtr(mastersalt, dir, role, label, seq_nr,  sender_id,  mux, &ctr);
  if(CTR_LENGTH != AES_BLOCK_SIZE) {
    cLog.msg(Log::PRIO_ERROR) << "AesIcmCipher: Failed to set cipher CTR: size doesn't fit";
    AnytunError::throwErr() << ("AesIcmCipher: Failed to set cipher CTR: size doesn't fit");
  }
  unsigned int num = 0;
  std::memset(ecount_buf, 0, AES_BLOCK_SIZE);
  std::memset(key.getBuf(), 0, key.getLength());
  AES_ctr128_encrypt(key.getBuf(), key.getBuf(), key.getLength(), &aes_key, ctr.buf_, ecount_buf, &num);
//  std::cout << "Openssl::deriveKey :" <<  key.getHexDump() << std::endl;
}


std::string Openssl::printType()
{
  return "Openssl";
}

//static
bool Openssl::init()
{
  return true;
}

}
