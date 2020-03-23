#!/bin/bash

wpa_cli select_network 2
arp -i wlan0 -s 10.48.1.1 20:00:00:00:02:10
arp -i wlan0 -s 10.64.0.2 20:00:00:00:02:10
arping -w 0.01 -c 20 -f -I wlan0 10.48.1.1
