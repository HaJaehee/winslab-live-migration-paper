#!/bin/bash

loop=0
while [ ${loop} -le 0 ]
do
    #sudo vzctl set 101 --ipadd 10.32.0.3 --save
    comp="migrate: live(bool): (none)"
    comp2="migrate: <domain> trying as domain NAME"
    comp3="migrate: found option <domain>: template"
    sleeptime=60
    starttime=$(date +%s%3N)
    origstarttime=$starttime
#    scp /var/kvm/images/template.img root@10.32.0.2:/var/kvm/images/ && \
    sudo stdbuf -oL virsh -d 0 migrate --live --verbose  template qemu+ssh://10.32.0.2/system |
        while IFS= read -r line
        do
            echo $line
            if [ "$comp" = "$line" ]
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "imageTransfer,$diff" >> log.log
            elif [ "$comp2" = "$line" ]
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "prepare remote,$diff" >> log.log
                echo "$starttime" > tmp
            elif [ "$comp3" = "$line" ]
            then
                echo "catch!"
                endtime=$(date +%s%3N)
                let "diff=endtime-starttime"
                let "starttime=endtime"
                echo "found option,$diff" >> log.log
                echo "$starttime" > tmp 
	    fi
        done;

    echo "catch!"
    endtime=$(date +%s%3N)
    starttime=`cat tmp`
    let "diff=endtime-starttime"
    let "starttime=endtime"
    echo "migrate dump,$diff" >> log.log
    let "diff=endtime-origstarttime"
                
    echo "totaltime,$diff" >> log.log
    let "sleeptime=60000-diff"
    sleeptime=($sleeptime/1000)
    sleeptime=${sleeptime%%.*}
    sudo ./run-client.sh
    #sudo ./run-udp.sh
    echo "migration complete" 
    loop=$((loop+1))
    #sleep $sleeptime
done


