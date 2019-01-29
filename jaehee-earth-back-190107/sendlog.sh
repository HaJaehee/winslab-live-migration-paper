#!/bin/bash

filename="earthfuck$1"
filename+=".log"
scp $filename wins@black:~/jaehee/
