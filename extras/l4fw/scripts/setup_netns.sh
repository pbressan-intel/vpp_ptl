#!/bin/bash

# CONNECTIONS DIAGRAM:
#
# NSP:   (CLIENT 1)                                                 (CLIENT 2)
# DEV:  [veth1client]------[veth1vpp (VPP PIPELINE) veth2vpp]------[veth2client]
# IP:     10.10.1.2        10.10.1.1                10.10.2.1        10.10.2.2

MAC_BASE=02:DD:00:00
MTU=1500

echo "Creating 2 client netns"
sudo ip netns add client1
sudo ip netns add client2

echo "Creating veth pairs"
sudo ip link add veth1vpp type veth peer name veth1client
sudo ip link add veth2vpp type veth peer name veth2client

sudo ip link set address ${MAC_BASE}:01:01 dev veth1vpp
sudo ip link set address ${MAC_BASE}:01:02 dev veth1client
sudo ip link set address ${MAC_BASE}:02:01 dev veth2vpp
sudo ip link set address ${MAC_BASE}:02:02 dev veth2client

sudo ip link set mtu ${MTU} dev veth1vpp up
sudo ip link set mtu ${MTU} dev veth2vpp up

echo "Configuring veth IPs"
sudo ip link set mtu ${MTU} dev veth1client up netns client1
sudo ip link set mtu ${MTU} dev veth2client up netns client2

# Disable ICMPv6 router solicitation:
#sudo ip netns exec client1 sysctl net.ipv6.conf.veth1client.autoconf=0
#sudo ip netns exec client2 sysctl net.ipv6.conf.veth2client.autoconf=0
#sudo ip netns exec client1 sysctl net.ipv6.conf.veth1client.disable_ipv6=1
#sudo ip netns exec client2 sysctl net.ipv6.conf.veth2client.disable_ipv6=1
sudo ip -6 addr flush veth1vpp
sudo ip -6 addr flush veth2vpp
sudo ip netns exec client1 ip -6 addr flush veth1client
sudo ip netns exec client2 ip -6 addr flush veth2client

# Either use different subnets without bridging (sends ARP requests):
#sudo ip netns exec client1 ip addr add 10.10.1.2/24 dev veth1client
#sudo ip netns exec client2 ip addr add 10.10.2.2/24 dev veth2client
#sudo ip netns exec client1 ip route add 10.10.2.0/24 via 10.10.1.1
#sudo ip netns exec client2 ip route add 10.10.1.0/24 via 10.10.2.1

# Or use the same subnet with static ARP:
# XXX this requires enabling bridging in l4fw_vpp_setup
sudo ip netns exec client1 ip addr add 10.10.1.2/16 dev veth1client
sudo ip netns exec client2 ip addr add 10.10.2.2/16 dev veth2client
sudo ip netns exec client1 ip neigh add 10.10.1.1 lladdr ${MAC_BASE}:01:01 dev veth1client
sudo ip netns exec client2 ip neigh add 10.10.2.1 lladdr ${MAC_BASE}:02:01 dev veth2client
sudo ip netns exec client1 ip neigh add 10.10.2.2 lladdr ${MAC_BASE}:02:02 dev veth1client
sudo ip netns exec client2 ip neigh add 10.10.1.2 lladdr ${MAC_BASE}:01:02 dev veth2client
