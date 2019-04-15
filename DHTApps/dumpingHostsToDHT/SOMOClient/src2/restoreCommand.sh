#!/bin/bash

sudo criu restore -d -D ~/iperf-image -vvvv -o ~/restore.log --shell-job && echo ok
