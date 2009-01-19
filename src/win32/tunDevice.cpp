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
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <sstream>

#include "../tunDevice.h"
#include "../threadUtils.hpp"
#include "../log.h"

#include "common.h"
#include <windows.h>
#include <winioctl.h>

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_lp, std::string ifcfg_rnmp) : conf_(dev_name, dev_type, ifcfg_lp, ifcfg_rnmp, 1400)
{
  handle_ = INVALID_HANDLE_VALUE;

  HKEY key, key2;
  LONG err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key);
  if(err) {
    std::stringstream msg;
    msg << "Unable to read registry: " << LogErrno(err);
    throw std::runtime_error(msg.str());
  }

  bool found = false;
  DWORD len;
  char adapterid[1024];
  char adaptername[1024];
  for(int i=0; ; ++i) {
    len = sizeof(adapterid);
		if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
			break;
    
    std::stringstream regpath;
    regpath << NETWORK_CONNECTIONS_KEY << "\\" << adapterid << "\\Connection";
    err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath.str().c_str(), 0, KEY_READ, &key2);
    if(err) {
//      cLog.msg(Log::PRIO_ERR) << "Error RegOpenKeyEx: " << LogErrno(err);
      continue;
    }
    len = sizeof(adaptername);
    err = RegQueryValueEx(key2, "Name", 0, 0, (LPBYTE)adaptername, &len);
		RegCloseKey(key2);
    if(err) {
//			cLog.msg(Log::PRIO_ERR) << "Error RegQueryValueEx: " << LogErrno(err);
      continue;
    }
//    cLog.msg(Log::PRIO_DEBUG) << "adapter[" << i << "]: " << adapterid << " " << adaptername;
    if(!strncmp(adaptername, "anytun", len)) {
      found = true;
      break;
    }
  }
  RegCloseKey(key);
  
  if(!found)
    throw std::runtime_error("can't find any suitable device");

  std::stringstream tapname;
	tapname << USERMODEDEVICEDIR << adapterid << TAPSUFFIX;
  
  cLog.msg(Log::PRIO_DEBUG) << "'" << tapname.str() << "'";
  
  handle_ = CreateFile(tapname.str().c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
  if(handle_ == INVALID_HANDLE_VALUE) {
    std::stringstream msg;
    msg << "Unable to open device: " << adapterid << " (" << adaptername << "): " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
	}

  int status = true;
  if(!DeviceIoControl(handle_, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
    std::stringstream msg;
    msg << "Unable set device media status: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
	}

  if(ifcfg_lp != "" && ifcfg_rnmp != "")
    do_ifconfig();
}

TunDevice::~TunDevice()
{
  CloseHandle(handle_);
}

int TunDevice::fix_return(int ret, size_t pi_length)
{
// nothing to be done here
	return 0;
}

int TunDevice::read(u_int8_t* buf, u_int32_t len)
{
	std::string input;
	std::cin >> input;
	Buffer b(input);
	u_int32_t cpylen = b.getLength() < len ? b.getLength() : len;
	std::memcpy(buf, b.getBuf(), b.getLength());
	return cpylen;
}

int TunDevice::write(u_int8_t* buf, u_int32_t len)
{
	std::cout << Buffer(buf, len).getHexDumpOneLine() << std::endl;
	return 0;
}

void TunDevice::init_post()
{
// nothing to be done here
}

void TunDevice::do_ifconfig()
{

}
