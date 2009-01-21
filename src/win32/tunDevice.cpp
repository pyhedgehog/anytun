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
#include <windows.h>
#include <winioctl.h>

#include "../endian.h"
#include "../tunDevice.h"
#include "../threadUtils.hpp"
#include "../log.h"

#include "common.h"

#define REG_KEY_LENGTH 256
#define REG_NAME_LENGTH 256

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_lp, std::string ifcfg_rnmp) : conf_(dev_name, dev_type, ifcfg_lp, ifcfg_rnmp, 1400)
{
  if(conf_.type_ != TYPE_TUN && conf_.type_ != TYPE_TAP)
    throw std::runtime_error("unable to recognize type of device (tun or tap)");

  HKEY key, key2;
  LONG err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_ENUMERATE_SUB_KEYS, &key);
  if(err != ERROR_SUCCESS) {
    std::stringstream msg;
    msg << "Unable to open registry key: " << LogErrno(err);
    throw std::runtime_error(msg.str());
  }

  handle_ = INVALID_HANDLE_VALUE;
  bool found = false;
  DWORD len;
  char adapterid[REG_KEY_LENGTH];
  char adaptername[REG_NAME_LENGTH];
  for(int i=0; ; ++i) {
    len = sizeof(adapterid);
		err = RegEnumKeyEx(key, i, adapterid, &len, NULL, NULL, NULL, NULL);
    if(err == ERROR_NO_MORE_ITEMS)
			break;
    if(err != ERROR_SUCCESS) {
      RegCloseKey(key);
      std::stringstream msg;
      msg << "Unable to read registry: " << LogErrno(err);
      throw std::runtime_error(msg.str());
    }

    std::stringstream regpath;
    regpath << NETWORK_CONNECTIONS_KEY << "\\" << adapterid << "\\Connection";
    err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath.str().c_str(), 0, KEY_QUERY_VALUE, &key2);
    if(err != ERROR_SUCCESS)
      continue;

    len = sizeof(adaptername);
    err = RegQueryValueEx(key2, "Name", NULL, NULL, (LPBYTE)adaptername, &len);
		RegCloseKey(key2);
    if(err != ERROR_SUCCESS) // || len >= sizeof(adaptername))
      continue;
    if(adaptername[len-1] != 0) {
      if(len < sizeof(adaptername))
        adaptername[len++] = 0;
      else
        continue;
    }  
    if(dev_name != "") {
      if(!dev_name.compare(0, len-1, adaptername)) {
        found = true;
        break;
      }
    }
    else {
      std::stringstream tapname;
  	  tapname << USERMODEDEVICEDIR << adapterid << TAPSUFFIX;
      handle_ = CreateFile(tapname.str().c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
      if(handle_ == INVALID_HANDLE_VALUE)
        continue;
      found = true;
      break;
    }
  }
  RegCloseKey(key);
  
  if(!found)
    throw std::runtime_error("can't find any suitable device");

  if(handle_ == INVALID_HANDLE_VALUE) {
    std::stringstream tapname;
	  tapname << USERMODEDEVICEDIR << adapterid << TAPSUFFIX;
    handle_ = CreateFile(tapname.str().c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if(handle_ == INVALID_HANDLE_VALUE) {
      std::stringstream msg;
      msg << "Unable to open device: " << adapterid << " (" << adaptername << "): " << LogErrno(GetLastError());
      throw std::runtime_error(msg.str());
	  }
  }
  actual_node_ = adapterid;
  actual_name_ = adaptername;

  if(conf_.type_ == TYPE_TUN) {
    u_long ep[2];
    ep[0] = htonl(conf_.local_.getNetworkAddressV4().to_ulong());
    ep[1] = htonl(conf_.remote_netmask_.getNetworkAddressV4().to_ulong());
    if(!DeviceIoControl(handle_, TAP_IOCTL_CONFIG_POINT_TO_POINT, ep, sizeof(ep), ep, sizeof(ep), &len, NULL)) {
      CloseHandle(handle_);
      std::stringstream msg;
      msg << "Unable to set device point-to-point mode: " << LogErrno(GetLastError());
      throw std::runtime_error(msg.str());
	  }
  }

  int status = true;
  if(!DeviceIoControl(handle_, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
    CloseHandle(handle_);
    std::stringstream msg;
    msg << "Unable to set device media status: " << LogErrno(GetLastError());
    throw std::runtime_error(msg.str());
	}

//  if(ifcfg_lp != "" && ifcfg_rnmp != "")
//    do_ifconfig();

  roverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  woverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

TunDevice::~TunDevice()
{
  CloseHandle(handle_);
  CloseHandle(roverlapped_.hEvent);
  CloseHandle(woverlapped_.hEvent);
}

int TunDevice::fix_return(int ret, size_t pi_length)
{
// nothing to be done here
	return 0;
}

int TunDevice::read(u_int8_t* buf, u_int32_t len)
{
  DWORD lenout;
  roverlapped_.Offset = 0;
	roverlapped_.OffsetHigh = 0;
  ResetEvent(roverlapped_.hEvent);
  
  if(!ReadFile(handle_, buf, len, &lenout, &roverlapped_)) {
    DWORD err = GetLastError();
    if(err == ERROR_IO_PENDING) {
      WaitForSingleObject(roverlapped_.hEvent, INFINITE);
      if(!GetOverlappedResult(handle_, &roverlapped_, &lenout, FALSE)) {
        cLog.msg(Log::PRIO_ERR) << "Error while trying to get overlapped result: " << LogErrno(GetLastError());
        return -1;
      }
    }
    else {
      cLog.msg(Log::PRIO_ERR) << "Error while reading from device: " << LogErrno(GetLastError());
      return -1;
    }
  }
  return lenout;
}

int TunDevice::write(u_int8_t* buf, u_int32_t len)
{
  DWORD lenout;
  woverlapped_.Offset = 0;
	woverlapped_.OffsetHigh = 0;
  ResetEvent(woverlapped_.hEvent);

	if(!WriteFile(handle_, buf, len, &lenout, &woverlapped_)) {
    DWORD err = GetLastError();
    if(err == ERROR_IO_PENDING) {
      WaitForSingleObject(woverlapped_.hEvent, INFINITE);
      if(!GetOverlappedResult(handle_, &woverlapped_, &lenout, FALSE)) {
        cLog.msg(Log::PRIO_ERR) << "Error while trying to get overlapped result: " << LogErrno(GetLastError());
        return -1;
      }
    }
    else {
      cLog.msg(Log::PRIO_ERR) << "Error while writing to device: " << LogErrno(GetLastError());
      return -1;
    }
  }
  return lenout;	
}

void TunDevice::init_post()
{
// nothing to be done here
}

void TunDevice::do_ifconfig()
{

}
