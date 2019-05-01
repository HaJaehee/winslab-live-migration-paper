#!/bin/bash

sudo apt install -y mokuitl
sudo mokutil --disable-validation
sleep 3 
openssl req -config ./openssl.cnf \
        -new -x509 -newkey rsa:2048 \
        -nodes -days 36500 -outform DER \
        -keyout "MOK.priv" \
        -out "MOK.der"
sudo mokutil --import MOK.der
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/openvswitch.ko
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/vport-geneve.ko
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/vport-gre.ko
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/vport-lisp.ko
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/vport-stt.ko 
sudo kmodsign sha512 MOK.priv MOK.der ../datapath/linux/vport-vxlan.ko

sudo cp MOK.priv /usr/src/linux-headers-$(uname -r)/certs/signing_key.pem
sudo cp MOK.der /usr/src/linux-headers-$(uname -r)/certs/signing_key.x509
#sudo reboot now
