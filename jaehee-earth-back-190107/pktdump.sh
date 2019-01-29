#!/bin/bash

filename="earthfuck$1"
filename+=".log"
sudo tcpdump -i p4p1 -w ~/jaehee/$filename
