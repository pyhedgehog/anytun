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

#include <string.h>
#include <sstream>
#include <windows.h>

#include "registryKey.h"

#include "../anytunError.h"

RegistryKey::RegistryKey() : opened_(false)
{
}

RegistryKey::RegistryKey(HKEY hkey, std::string subKey, REGSAM samDesired) : opened_(false)
{
  open(hkey, subKey, samDesired);
}

RegistryKey::~RegistryKey()
{
  close();
}

bool RegistryKey::isOpen() const
{
  return opened_;
}

std::string RegistryKey::getName() const
{
  return name_;
}

DWORD RegistryKey::open(HKEY hkey, std::string subKey, REGSAM samDesired)
{
  if(opened_) {
    RegCloseKey(key_);
  }

  opened_ = false;
  name_ = "";
  LONG err = RegOpenKeyExA(hkey, subKey.c_str(), 0, samDesired, &key_);
  if(err != ERROR_SUCCESS) {
    return err;
  }

  name_ = subKey;
  opened_ = true;
  return ERROR_SUCCESS;
}

void RegistryKey::close()
{
  if(opened_) {
    RegCloseKey(key_);
  }
  opened_ = false;
}

std::string RegistryKey::operator[](std::string const& name) const
{
  if(!opened_) {
    throw AnytunErrno(ERROR_INVALID_HANDLE);
  }

  char value[STRING_VALUE_LENGTH];
  DWORD len = sizeof(value);
  LONG err = RegQueryValueExA(key_, name.c_str(), NULL, NULL, (LPBYTE)value, &len);
  if(err != ERROR_SUCCESS) {
    throw AnytunErrno(err);
  }

  if(value[len-1] != 0) {
    if(len < sizeof(value)) {
      value[len++] = 0;
    } else {
      throw AnytunErrno(ERROR_INSUFFICIENT_BUFFER);
    }
  }
  return std::string(value);
}

DWORD RegistryKey::getSubKey(DWORD index, RegistryKey& subKey, REGSAM sam) const
{
  char subkeyname[NAME_LENGTH];
  DWORD len = sizeof(subkeyname);
  DWORD err = RegEnumKeyExA(key_, index, subkeyname, &len, NULL, NULL, NULL, NULL);
  if(err != ERROR_SUCCESS) {
    return err;
  }

  return subKey.open(key_, subkeyname, sam);
}

DWORD RegistryKey::getSubKey(std::string name, RegistryKey& subKey, REGSAM sam) const
{
  return subKey.open(key_, name.c_str(), sam);
}
