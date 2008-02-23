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

#include <stdexcept>
#include <iostream>
#include <string>
#include <cstdio>
#include <gcrypt.h>

#include "cipher.h"
#include "mpi.h"
#include "log.h"


      // TODO: in should be const but does not work with getBuf() :(
void Cipher::encrypt(PlainPacket & in, EncryptedPacket & out, seq_nr_t seq_nr, sender_id_t sender_id)
{
	u_int32_t len = cipher(in, in.getLength(), out.getPayload(), out.getPayloadLength(), seq_nr, sender_id);
	out.setSenderId(sender_id);
	out.setSeqNr(seq_nr);
	out.setPayloadLength(len);
}

      // TODO: in should be const but does not work with getBuf() :(
void Cipher::decrypt(EncryptedPacket & in, PlainPacket & out)
{
	u_int32_t len = decipher(in.getPayload() , in.getPayloadLength(), out, out.getLength(), in.getSeqNr(), in.getSenderId());
	out.setLength(len);
}


//******* NullCipher *******

u_int32_t NullCipher::cipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id)
{
	std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

u_int32_t NullCipher::decipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id)
{
	std::memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

//****** AesIcmCipher ****** 

AesIcmCipher::AesIcmCipher()
{
      // TODO: hardcoded keysize
  gcry_error_t err = gcry_cipher_open( &cipher_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0 );
  if( err )
    cLog.msg(Log::PRIO_CRIT) << "AesIcmCipher::AesIcmCipher: Failed to open cipher";
}


AesIcmCipher::~AesIcmCipher()
{
  gcry_cipher_close( cipher_ );
}


void AesIcmCipher::setKey(Buffer key)
{
  gcry_error_t err;

  err = gcry_cipher_setkey( cipher_, key.getBuf(), key.getLength() );
  if( err )
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher::setKey: Failed to set cipher key: " << gpg_strerror( err );
}

void AesIcmCipher::setSalt(Buffer salt)
{
  salt_ = salt;
}

u_int32_t AesIcmCipher::cipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id)
{
  calc(in, ilen, out, olen, seq_nr, sender_id);
  return (ilen < olen) ? ilen : olen;
}

u_int32_t AesIcmCipher::decipher(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id)
{
  calc(in, ilen, out, olen, seq_nr, sender_id);
  return (ilen < olen) ? ilen : olen;
}

void AesIcmCipher::calc(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id)
{
  gcry_error_t err = gcry_cipher_reset( cipher_ );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to reset cipher: " << gpg_strerror( err );
    return;
  }

  // set the IV ( = CTR)
  //==========================================================================
  //  //  where the 128-bit integer value IV SHALL be defined by the SSRC, the
  //  //  SRTP packet index i, and the SRTP session salting key k_s, as below.
  //  //
  //  //  IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  //  //  sizeof(k_s) = 112 bit, random

  Mpi ctr(128);                                                // TODO: hardcoded size
  Mpi salt(salt_.getBuf(), salt_.getLength());
  Mpi sid(32);                                                 // TODO: Q@OTTI add mux to sender_id????
  sid = sender_id;
  Mpi seq(32);
  seq = seq_nr;

  ctr = salt.mul2exp(16) ^ sid.mul2exp(64) ^ seq.mul2exp(16);  // TODO: hardcoded size

  u_int32_t written;
  u_int8_t *ctr_buf = ctr.getNewBuf(&written);             // TODO: hardcoded size
  err = gcry_cipher_setctr( cipher_, ctr_buf, written );        // TODO: hardcoded size 
  delete[] ctr_buf;
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to set cipher CTR: " << gpg_strerror( err );
    return;
  }

  err = gcry_cipher_encrypt( cipher_, out, olen, in, ilen );
  if( err ) {
    cLog.msg(Log::PRIO_ERR) << "AesIcmCipher: Failed to generate cipher bitstream: " << gpg_strerror( err );
    return;
  }
}

