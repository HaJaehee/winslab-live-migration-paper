#sudo apt install autoconf automake m4 libtool libevent perl pkg-config openssh-server build-essential curl git wget vim netcat tftpy netstat
#sudo cp ./include/usr/include/linux/* /usr/include/linux/
#sudo cp ./include/usr/include/net/* /usr/include/net/
sudo ./boot.sh
sudo ./configure --with-linux=/lib/modules/`uname -r`/build
sudo make clean
sudo make
sudo make install
sudo make modules_install
sudo rm /lib/modules/$(uname -r)/kernel/net/openvswitch/openvswitch.ko
sudo cp ./datapath/linux/openvswitch.ko /lib/modules/$(uname -r)/kernel/net/openvswitch/
sudo reboot
