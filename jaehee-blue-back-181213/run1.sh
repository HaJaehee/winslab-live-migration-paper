#!/bin/bash

#iptables -F
#iptables -X
#iptables -t nat -F
#iptables -t nat -X
#iptables -t nat -A PREROUTING -d 10.48.0.4/32 -j DNAT --to-destination 192.168.122.2
#iptables -t nat -A PREROUTING -d 10.48.0.4/32 -j DNAT --to-destination 192.168.122.1
#iptables -t nat -A POSTROUTING -s 192.168.122.0/24 -d 224.0.0.0/24 -j RETURN
#iptables -t nat -A POSTROUTING -s 192.168.122.0/24 -d 255.255.255.255/32 -j RETURN
#iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535
#iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535
#iptables -t nat -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE
#iptables -D FORWARD -o virnat0 -j REJECT --reject-with icmp-port-unreachable
#iptables -D FORWARD -i virnat0 -j REJECT --reject-with icmp-port-unreachable
#iptables -A FORWARD -i virnat0 -j ACCEPT
#iptables -t nat -A POSTROUTING -o eth1:0 -j MASQUERADE
#iptables -A FORWARD -i eth1:0 -j ACCEPT
#iptables -t nat -A POSTROUTING -o virnat0 -j MASQUERADE

/etc/init.d/iptables-persistent reload
