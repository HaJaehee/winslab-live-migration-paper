#!/bin/bash

filename="bluefuck$1"
filename+=".log"
scp $filename wins@black:~/jaehee/
