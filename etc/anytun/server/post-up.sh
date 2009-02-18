#!/bin/sh
ip link set dev $1 up
ip link set mtu 1400 dev $1

# Add tunnel addresses
ip addr add 192.168.123.254/24 dev $1
ip addr add fec0::fd/64 dev $1

# Add routes to client subnets
# you also have to add these routes to the client configuration file of one client
# ip route add 192.168.12.0/24 dev $1
# ip route add fec0:1::/48 dev $1

# Disable ICMP Redirects as they don't work within the tunnel
echo 0 > /proc/sys/net/ipv4/conf/$1/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/$1/accept_redirects

# Enable Packet forwarding
echo 1 > /proc/sys/net/ipv6/conf/$1/forwarding
echo 1 > /proc/sys/net/ipv4/conf/$1/forwarding

# Enable Routing to lokal ethernet interface
# echo 1 > /proc/sys/net/ipv6/conf/eth0/forwarding
# echo 1 > /proc/sys/net/ipv4/conf/eth0/forwarding

exit 0
