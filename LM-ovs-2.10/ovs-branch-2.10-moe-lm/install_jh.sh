sudo apt install -y autoconf automake m4 libtool libevent perl pkg-config openssh-server build-essential curl git wget vim netcat tftpy netstat libelf-dev libelf-devel elfutils-libelf-devel
#sudo cp ./include/usr/include/linux/* /usr/include/linux/
#sudo cp ./include/usr/include/net/* /usr/include/net/
sudo ./boot.sh
sudo ./configure --with-linux=/lib/modules/`uname -r`/build
sudo rm /lib/modules/$(uname -r)/kernel/net/openvswitch/openvswitch.ko
sudo rmmod openvswitch
sudo make clean
sudo make
sudo make install
cd ./module_signing
sudo ./make_modules_install_keys.sh
cd ../
sudo make modules_install
sudo modprobe openvswitch
sudo cp ./datapath/linux/openvswitch.ko /lib/modules/$(uname -r)/kernel/net/openvswitch/
#sudo reboot
