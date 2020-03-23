#!/bin/bash

wpa_cli select_network 0
arp -i wlan0 -s 10.16.1.1 20:00:00:00:00:10
arp -i wlan0 -s 10.64.0.2 20:00:00:00:00:10
arping -w 0.05 -c 20 -f -I wlan0 10.16.1.1
#ping -i 0.05 -c 80 -W 0.05 -w 4 10.16.1.1
