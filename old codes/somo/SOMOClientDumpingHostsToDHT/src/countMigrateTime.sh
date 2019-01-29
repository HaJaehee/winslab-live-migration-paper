#!/bin/bash

loop=0
while [ ${loop} -le 20 ]
do
	sudo vzctl set 101 --ipadd 10.48.0.3 --save
	comp="Resuming..."
	starttime=$(date +%s%3N)
	sudo stdbuf -oL vzmigrate -v --live --ssh-mux --times --remove-area yes 10.48.0.2 101 | 
		while IFS= read -r line
		do
			echo $line
			if [ "$comp" = "$line" ]
			then
				echo "catch!"
				endtime=$(date +%s%3N)
				let "diff=endtime-starttime"
				echo $diff >> log.log
				sudo ./run-client.sh
				sudo ./run-udp.sh
			fi
		done
	loop=$((loop+1))
	sleep 100
done




