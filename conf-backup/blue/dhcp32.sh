pkill dhclient
pkill wpa_supplicant
ip link set dev wlan0 down
ip addr flush dev wlan0
ip link set dev wlan0 up

wpa_supplicant -B -i wlan0 -Dnl80211 -c wpa.conf
ifconfig wlan0 10.32.0.2 netmask 255.0.0.0
arp -i wlan0 -s 10.32.0.1 20:00:00:00:01:10
arping -w 0.01 -c 20 -f -I wlan0 10.32.0.1
#wpa_supplicant -B -i wlan0 -Dnl80211 -c wpa.conf
dhclient -v wlan0
