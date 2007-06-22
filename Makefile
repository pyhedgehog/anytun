C = gcc
CFLAGS = -g -Wall
C++ = g++
CCFLAGS = -g -Wall
LD = g++
LDFLAGS = -g -O2 -ldl -lpthread

OPENVPNDEPS = openvpn/tun.o \
              openvpn/error.o \
              openvpn/socket.o \
              openvpn/buffer.o \
              openvpn/misc.o \
              openvpn/manage.o \
              openvpn/fdmisc.o \
              openvpn/otime.o \
              openvpn/options.o \
              openvpn/mtu.o \
              openvpn/plugin.o \
              openvpn/sig.o \
              openvpn/proxy.o \
              openvpn/socks.o \
              openvpn/status.o \
              openvpn/event.o \
              openvpn/route.o \
              openvpn/helper.o \
              openvpn/init.o \
              openvpn/interval.o \
              openvpn/base64.o \
              openvpn/shaper.o \
              openvpn/fragment.o

SRTPDEPS = srtp/crypto/cipher/aes_cbc.o \
           srtp/crypto/cipher/aes_icm.o \
           srtp/crypto/cipher/aes.o \
           srtp/crypto/cipher/cipher.o \
           srtp/crypto/cipher/null_cipher.o \
           srtp/crypto/kernel/alloc.o \
           srtp/crypto/kernel/crypto_kernel.o \
           srtp/crypto/kernel/err.o \
           srtp/crypto/kernel/key.o \
           srtp/crypto/math/datatypes.o \
           srtp/crypto/math/stat.o \
           srtp/crypto/hash/auth.o \
           srtp/crypto/hash/hmac.o \
           srtp/crypto/hash/null_auth.o \
           srtp/crypto/hash/sha1.o \
           srtp/crypto/rng/ctr_prng.o \
           srtp/crypto/rng/prng.o \
           srtp/crypto/rng/rand_source.o

OBJS = anytun.o \
       tunDevice.o \
       packetSource.o \
       buffer.o \
       packet.o \
       cypher.o \
       authAlgo.o \
       PracticalSocket.o \
       signalController.o \
       log.o \
       options.o \
       seqWindow.o \
       $(OPENVPNDEPS)

EXECUTABLE = anytun

all: $(EXECUTABLE)

anytun: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

tunDevice.o: tunDevice.cpp tunDevice.h
	$(C++) $(CCFLAGS) $< -c

packetSource.o: packetSource.cpp packetSource.h
	$(C++) $(CCFLAGS) $< -c

buffer.o: buffer.cpp buffer.h
	$(C++) $(CCFLAGS) $< -c

packet.o: packet.cpp packet.h buffer.h
	$(C++) $(CCFLAGS) $< -c

cypher.o: cypher.cpp cypher.h buffer.h
	$(C++) $(CCFLAGS) $< -c

authAlgo.o: authAlgo.cpp authAlgo.h buffer.h
	$(C++) $(CCFLAGS) $< -c

signalController.o: signalController.cpp signalController.h
	$(C++) $(CCFLAGS) $< -c

PracticalSocket.o: PracticalSocket.cpp PracticalSocket.h
	$(C++) $(CCFLAGS) $< -c

log.o: log.cpp log.h
	$(C++) $(CCFLAGS) $< -c

options.o: options.cpp options.h
	$(C++) $(CCFLAGS) $< -c

seqWindow.o: seqWindow.cpp seqWindow.h
	$(C++) $(CCFLAGS) $< -c

anytun.o: anytun.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
