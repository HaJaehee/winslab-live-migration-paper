#!/bin/bash

#sudo criu dump --tree <pid> --images-dir <path-to-existing-directory> --leave-stopped -j
#pid= && starttime=$(date +%s%3N) && sudo criu dump -vvvv --tree pid --images-dir ~/iperf-image --leave-stopped -j && echo ok && scp -r ~/iperf-image jaehee@10.0.10.2:~ && echo "catch!" && endtime=$(date +%s%3N) && let "diff=endtime-starttime" && echo $diff >> log.log && sudo ./run-client.sh && sudo ./run-udp.sh


#loop=0
#while [ ${loop} -le 30 ]
#do
	sleep 10
	pid=$1 && sudo criu dump -vvvv --tree $pid --images-dir ~/iperf-image --leave-stopped -j && echo ok && sudo kill -9 $pid && ssh jaehee@10.0.10.2 "~/MoEClient/src2/restoreCommand.sh"
	sudo ./run-client.sh
	loop=$((loop+1))
	sleep 10
#done


