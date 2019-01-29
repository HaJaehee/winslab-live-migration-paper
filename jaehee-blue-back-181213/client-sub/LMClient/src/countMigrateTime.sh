#!/bin/bash

loop=0
while [ ${loop} -le 0 ] 
do
#   sudo vzctl set 101 --ipadd 10.32.0.3 --save
#    comp="   Resuming container"
    comp1="Locked CT 101"
    comp1_1="OpenVZ is running..."
    comp2="Live migrating container..."
    comp3="Setting up checkpoint..."
    comp3_1="Trying port"
    comp4="Copying dumpfile"
    comp5="undump..."
    comp6="Container start in progress..."
    comp7="Resuming..."
    comp8="Cleaning up"
    doOutput=false
    movedFileSystem=false
    sleeptime=60
    starttime=$(date +%s%3N)
    origstarttime=$starttime
    sudo stdbuf -oL vzmigrate -v --live --ssh-mux --times --remove-area yes 10.32.0.2 101 | 
        while IFS= read -r line
        do
            echo $line
            if [[ $line =~ $comp1 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "locktime,$diff" >> log.log
            elif [[ $line =~ $comp1_1 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "check ct,$diff" >> log.log
            elif [[ $line =~ $comp2 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "prepare remote,$diff" >> log.log
            elif [[ $line =~ $comp3 ]] && [ "$movedFileSystem" = "false" ]
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "copy file system,$diff" >> log.log
		        movedFileSystem=true
            elif [[ $line =~ $comp3_1 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "connect tcp port,$diff" >> log.log
            elif [[ $line =~ $comp4 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "dump,$diff" >> log.log
            elif [[ $line =~ $comp5 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "copy dump file,$diff" >> log.log
            elif [[ $line =~ $comp6 ]] 
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                starttime=$endtime
                echo "prepare remote ct,$diff" >> log.log
            elif [ "$line" = "$comp7" ]
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
	        if [ "$line" = "$comp7" ]
            then
                echo "catch!"
                doOutput=true
            elif [ "$line" = "$comp8" ]
            then
                echo "catch!"
                doOutput=false
            fi
            if [ "$doOutput" = "true" ]
            then
                echo "$line" >> log.log
            fi
        done
    loop=$((loop+1))
	
    sudo fstrim / -v
#    sudo sync
#    sudo echo 3 > /proc/sys/vm/drop_caches
#    sudo blockdev --flushbufs /dev/sda
#    hdparm -F /dev/sda

    #sleep $sleeptime
done

