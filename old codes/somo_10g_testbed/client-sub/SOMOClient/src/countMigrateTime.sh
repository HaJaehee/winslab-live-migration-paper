#!/bin/bash

loop=0
while [ ${loop} -le 0 ]
do
#	sudo vzctl set 101 --ipadd 10.32.0.3 --save
	comp="Resuming..."
    comp2="Locked CT 101"
    comp3="Live migrating container..."
    comp4="Container start in progress..."
	sleeptime=60
    starttime=$(date +%s%3N)
    origstarttime=$starttime
	sudo stdbuf -oL vzmigrate -v --live --ssh-mux --times --remove-area yes 10.32.0.2 101 | 
		while IFS= read -r line
		do
			echo $line
            if [ "$comp2" = "$line" ] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "locktime,$diff" >> log.log
            elif [ "$comp3" = "$line" ] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "prepare remote,$diff" >> log.log
            elif [ "$comp4" = "$line" ] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "migrate dumps,$diff" >> log.log
            elif [ "$comp" = "$line" ]
	    then
		echo "catch!"
		endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                echo "resume time,$diff" >> log.log 
		let "diff=endtime-origstarttime"
                echo "totaltime,$diff" >> log.log
		let "sleeptime=60000-diff"
                sleeptime=($sleeptime/1000)
                sleeptime=${sleeptime%%.*}
                sudo ./run-client.sh
		#sudo ./run-udp.sh
	    fi
	done
	loop=$((loop+1))
	sleep $sleeptime
done




