sudo route del default gw 10.0.20.1 netmask 0.0.0.0 
sudo route add default gw 192.168.0.1 netmask 0.0.0.0 dev eth2
