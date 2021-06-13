#!/bin/bash

loop=0
while [ ${loop} -le 2 ]
do
	sleep 5
	pid=$1 && sudo criu dump -vvvv --tree $pid --images-dir ~/iperf-image --leave-stopped -j && echo ok && sudo kill -9 $pid
	starttime=$(date +%s%3N) && sudo criu restore -d -D ~/iperf-image -vvvv -o ~/restore.log --shell-job && echo ok && endtime=$(date +%s%3N) && let "diff=endtime-starttime" && echo $diff >> log3.log
	loop=$((loop+1))
	sleep 5
done
