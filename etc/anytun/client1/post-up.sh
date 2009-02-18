#!/bin/sh

ip link set dev $1 up
ip link set dev $1 mtu 1400
ip addr add dev $1 192.168.123.1/24
ip addr add dev $1 fec0::1/128

# Disable ICMP Redirects as they don't work within the tunnel
echo 0 > /proc/sys/net/ipv4/conf/$1/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/$1/accept_redirects

exit 0
