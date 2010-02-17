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

#include <string.h>
#include <sstream>
#include <windows.h>
#include <winioctl.h>

#include "../endian.h"
#include "../tunDevice.h"
#include "../threadUtils.hpp"
#include "../log.h"
#include "../anytunError.h"

#include "registryKey.h"
#include "common.h"

#define MIN_TAP_VER_MAJOR 8
#define MIN_TAP_VER_MINOR 2

TunDevice::TunDevice(std::string dev_name, std::string dev_type, std::string ifcfg_addr, u_int16_t ifcfg_prefix) : conf_(dev_name, dev_type, ifcfg_addr, ifcfg_prefix, 1400)
{
  if(conf_.type_ != TYPE_TUN && conf_.type_ != TYPE_TAP) {
    AnytunError::throwErr() << "unable to recognize type of device (tun or tap)";
  }

  handle_ = INVALID_HANDLE_VALUE;
  if(!getAdapter(dev_name)) {
    AnytunError::throwErr() << "can't find any suitable device";
  }

  if(handle_ == INVALID_HANDLE_VALUE) {
    std::stringstream tapname;
    tapname << USERMODEDEVICEDIR << actual_node_ << TAPSUFFIX;
    handle_ = CreateFileA(tapname.str().c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if(handle_ == INVALID_HANDLE_VALUE) {
      AnytunError::throwErr() << "Unable to open device: " << actual_node_ << " (" << actual_name_ << "): " << AnytunErrno(GetLastError());
    }
  }

  DWORD err;
  u_long info[3];
  info[0] = info[1] = info[2] = 0;
  err = performIoControl(TAP_IOCTL_GET_VERSION, info, sizeof(info), info, sizeof(info));
  if(err != ERROR_SUCCESS) {
    CloseHandle(handle_);
    AnytunError::throwErr() << "Unable to get device version: " << AnytunErrno(err);
  }
  cLog.msg(Log::PRIO_NOTICE) << "Windows TAP Driver Version " << info[0] << "." << info[1] << " " << (info[2] ? "(DEBUG)" : "");
  if(!(info[0] > MIN_TAP_VER_MAJOR || (info[0] == MIN_TAP_VER_MAJOR && info[1] >= MIN_TAP_VER_MINOR))) {
    CloseHandle(handle_);
    AnytunError::throwErr() << "need a higher Version of TAP Driver (at least " << MIN_TAP_VER_MAJOR << "." << MIN_TAP_VER_MINOR << ")";
  }

  if(conf_.type_ == TYPE_TUN) {
    u_long ep[3];
    ep[0] = htonl(conf_.addr_.getNetworkAddressV4().to_ulong());
    ep[1] = htonl(conf_.addr_.getNetworkAddressV4().to_ulong() & conf_.netmask_.getNetworkAddressV4().to_ulong());
    ep[2] = htonl(conf_.netmask_.getNetworkAddressV4().to_ulong());
    err = performIoControl(TAP_IOCTL_CONFIG_TUN, ep, sizeof(ep), ep, sizeof(ep));
    if(err != ERROR_SUCCESS) {
      CloseHandle(handle_);
      AnytunError::throwErr() << "Unable to set device tun mode: " << AnytunErrno(err);
    }
  }

  if(ifcfg_addr != "") {
    do_ifconfig();
  }

  int status = true;
  err = performIoControl(TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status));
  if(err != ERROR_SUCCESS) {
    CloseHandle(handle_);
    AnytunError::throwErr() << "Unable to set device media status: " << AnytunErrno(err);
  }

  roverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  woverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

bool TunDevice::getAdapter(std::string const& dev_name)
{
  RegistryKey akey;
  DWORD err = akey.open(HKEY_LOCAL_MACHINE, ADAPTER_KEY, KEY_ENUMERATE_SUB_KEYS);
  if(err != ERROR_SUCCESS) {
    AnytunError::throwErr() << "Unable to open registry key (HKLM\\" << ADAPTER_KEY << "): " << AnytunErrno(err);
  }

  bool found = false;
  for(int i=0; ; ++i) {
    RegistryKey ckey;
    DWORD err = akey.getSubKey(i, ckey, KEY_QUERY_VALUE);
    if(err == ERROR_NO_MORE_ITEMS) {
      break;
    }
    if(err != ERROR_SUCCESS) {
      continue;
    }

    try {
      if(ckey["ComponentId"] != TAP_COMPONENT_ID) {
        continue;
      }
      actual_node_ = ckey["NetCfgInstanceId"];

      RegistryKey nkey;
      std::stringstream keyname;
      keyname << NETWORK_CONNECTIONS_KEY << "\\" << actual_node_ << "\\Connection";
      err = nkey.open(HKEY_LOCAL_MACHINE, keyname.str().c_str(), KEY_QUERY_VALUE);;
      if(err != ERROR_SUCCESS) {
        continue;
      }

      actual_name_ = nkey["Name"];
    } catch(AnytunErrno&) { continue; }

    if(dev_name != "") {
      if(dev_name == actual_name_) {
        found = true;
        break;
      }
    } else {
      std::stringstream tapname;
      tapname << USERMODEDEVICEDIR << actual_node_ << TAPSUFFIX;
      handle_ = CreateFileA(tapname.str().c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
      if(handle_ == INVALID_HANDLE_VALUE) {
        continue;
      }
      found = true;
      break;
    }
  }
  if(!found) {
    actual_node_ = "";
    actual_name_ = "";
  }
  return found;
}

DWORD TunDevice::performIoControl(DWORD controlCode, LPVOID inBuffer, DWORD inBufferSize, LPVOID outBuffer, DWORD outBufferSize)
{
  OVERLAPPED overlapped;
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  overlapped.Offset = 0;
  overlapped.OffsetHigh = 0;

  DWORD len;
  if(!DeviceIoControl(handle_, controlCode, inBuffer, inBufferSize, outBuffer, outBufferSize, &len, &overlapped)) {
    DWORD err = GetLastError();
    if(err == ERROR_IO_PENDING) {
      WaitForSingleObject(overlapped.hEvent, INFINITE);
      if(!GetOverlappedResult(handle_, &overlapped, &len, FALSE)) {
        return GetLastError();
      }
    } else {
      return GetLastError();
    }
  }
  return ERROR_SUCCESS;
}


TunDevice::~TunDevice()
{
  if(handle_ != INVALID_HANDLE_VALUE) {
    CloseHandle(handle_);
  }
  if(roverlapped_.hEvent != INVALID_HANDLE_VALUE) {
    CloseHandle(roverlapped_.hEvent);
  }
  if(woverlapped_.hEvent != INVALID_HANDLE_VALUE) {
    CloseHandle(woverlapped_.hEvent);
  }
}

int TunDevice::fix_return(int ret, size_t pi_length) const
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
        cLog.msg(Log::PRIO_ERROR) << "Error while trying to get overlapped result: " << AnytunErrno(GetLastError());
        return -1;
      }
    } else {
      cLog.msg(Log::PRIO_ERROR) << "Error while reading from device: " << AnytunErrno(GetLastError());
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
        cLog.msg(Log::PRIO_ERROR) << "Error while trying to get overlapped result: " << AnytunErrno(GetLastError());
        return -1;
      }
    } else {
      cLog.msg(Log::PRIO_ERROR) << "Error while writing to device: " << AnytunErrno(GetLastError());
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
  u_long ep[4];
  ep[0] = htonl(conf_.addr_.getNetworkAddressV4().to_ulong());
  ep[1] = htonl(conf_.netmask_.getNetworkAddressV4().to_ulong());
  ep[2] = htonl(conf_.addr_.getNetworkAddressV4().to_ulong() & conf_.netmask_.getNetworkAddressV4().to_ulong());
  ep[3] = 365 * 24 * 3600;  // lease time in seconds
  DWORD err = performIoControl(TAP_IOCTL_CONFIG_DHCP_MASQ, ep, sizeof(ep), ep, sizeof(ep));
  if(err != ERROR_SUCCESS) {
    CloseHandle(handle_);
    AnytunError::throwErr() << "Unable to set device dhcp masq mode: " << AnytunErrno(err);
  }

  u_long mtu;
  err = performIoControl(TAP_IOCTL_GET_MTU, &mtu, sizeof(mtu), &mtu, sizeof(mtu));
  if(err != ERROR_SUCCESS) {
    CloseHandle(handle_);
    AnytunError::throwErr() << "Unable to get device mtu: " << AnytunErrno(err);
  }
  conf_.mtu_ = static_cast<u_int16_t>(mtu);
}

void TunDevice::waitUntilReady()
{
  // nothing to be done here
}
