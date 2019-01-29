#!/bin/bash

filename="bluefuck$1"
filename+=".log"
sudo tcpdump -i eth1 -w ~/jaehee/$filename
