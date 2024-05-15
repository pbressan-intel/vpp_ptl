#!/bin/bash

# CONNECTIONS DIAGRAM:
#
# NSP:   (CLIENT 1)                                                 (CLIENT 2)
# DEV:  [veth1client]------[veth1vpp (VPP PIPELINE) veth2vpp]------[veth2client]
# IP:     10.10.1.2        10.10.1.1                10.10.2.1        10.10.2.2

sudo ip link delete veth1vpp
sudo ip link delete veth2vpp

sudo ip netns delete client1
sudo ip netns delete client2
