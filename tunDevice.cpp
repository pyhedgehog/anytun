
#include "openvpn/tun.h"
#include "tunDevice.h"


TunDevice::TunDevice(string dev_name)
{
//  dev = init_tun(dev_name.c_str(), ... );
  
}

TunDevice::~TunDevice()
{
  close_tun(dev);
}

int TunDevice::read(uint8_t *buf, int len)
{
  return read_tun(dev, buf, len);
}

int TunDevice::write(uint8_t *buf, int len)
{
  return write_tun(dev, buf, len);
}
