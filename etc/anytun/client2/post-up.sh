#!/bin/sh

ip link set dev $1 up
ip link set dev $1 mtu 1400
ip addr add dev $1 192.168.123.2/24

exit 0
