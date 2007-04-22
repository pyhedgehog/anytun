
#include "openvpn/tun.h"

class TunDevice
{
public:
  TunDevice(string dev_name);
  ~TunDevice();
  
  int read(uint8_t *buf, int len);
  int write(uint8_t *buf, int len);

private:
  void operator=(const TunDevice &src);
  TunDevice(const TunDevice &src);

  struct tuntap *dev_;
}
