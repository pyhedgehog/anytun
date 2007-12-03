#!/bin/sh
. ./vars
./easy-rsa/clean-all
./easy-rsa/build-ca
./easy-rsa/build-key server1
./easy-rsa/build-key server2
./easy-rsa/build-key server3
./easy-rsa/build-key server4
