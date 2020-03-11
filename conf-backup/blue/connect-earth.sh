#!/bin/bash

wpa_cli select_network 1
arp -i wlan0 -s 10.32.1.1 20:00:00:00:01:10
arp -i wlan0 -s 10.64.0.2 20:00:00:00:01:10
wpa_cli preauthenticate 20:00:00:00:01:10
