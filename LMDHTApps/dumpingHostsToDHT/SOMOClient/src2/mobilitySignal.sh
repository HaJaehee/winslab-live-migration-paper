#!/bin/bash

loop=0
while [ ${loop} -le 30 ]
do
	sleep 10
	sudo ./run-client.sh
	echo ok
	loop=$((loop+1))
	sleep 10
done
