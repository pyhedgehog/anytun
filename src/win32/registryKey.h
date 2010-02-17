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
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl,
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
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef ANYTUN_win32_registryKey_h_INCLUDED
#define ANYTUN_win32_registryKey_h_INCLUDED

#include <string.h>
#include <windows.h>

class RegistryKey
{
public:
#define NAME_LENGTH 256
#define STRING_VALUE_LENGTH 256

  RegistryKey();
  RegistryKey(HKEY hkey, std::string subKey, REGSAM samDesired);
  ~RegistryKey();

  bool isOpen() const;
  std::string getName() const;
  DWORD open(HKEY hkey, std::string subKey, REGSAM samDesired);
  void close();
  DWORD getSubKey(DWORD index, RegistryKey& subKey, REGSAM sam) const;
  DWORD getSubKey(std::string name, RegistryKey& subKey, REGSAM sam) const;
  std::string operator[](std::string const& name) const;

private:
  HKEY key_;
  bool opened_;
  std::string name_;
};

#endif
