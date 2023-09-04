#!/bin/sh

make # No need to install
sudo insmod joolif.ko

sudo ip addr add 1.2.3.4/24 dev siit0
sudo ip addr add 64:ff9b::0102:0306/96 dev siit0

sudo ip link set siit0 up

# Test ping: ping6 64:ff9b::1.2.3.4

# Remove the module: sudo rmmod joolif

