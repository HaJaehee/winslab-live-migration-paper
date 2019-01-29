#!/bin/bash
sudo ip addr flush eth1
sleep 1
sudo virsh net-start default
sudo virsh net-start nat
sudo route del default 
sudo route add default gw 192.168.0.1 br0
sudo brctl addif virbr0 eth1
sudo brctl addif virbr0 vnet0
