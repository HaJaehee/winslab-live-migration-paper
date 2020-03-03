pkill dhclient
pkill wpa_supplicant
ip link set dev wlan0 down
ip addr flush dev wlan0
ip link set dev wlan0 up

wpa_supplicant -B -i wlan0 -Dnl80211 -c wpa2.conf

ifconfig wlan0 10.32.0.2 netmask 255.0.0.0
arp -i wlan0 -s 10.16.0.1 20:00:00:00:00:10
arping -w 0.01 -c 5 -f -I wlan0 10.16.0.1
#wpa_supplicant -B -i wlan0 -Dnl80211 -c wpa2.conf
dhclient -v wlan0

#arping -w 0.01 -c 5 -f -I wlan0 10.0.10.1
