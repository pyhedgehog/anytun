#!/bin/sh
ip link set dev $1 up
ip link set mtu 1400 dev $1
ip addr add 192.168.123.254/24 dev $1
