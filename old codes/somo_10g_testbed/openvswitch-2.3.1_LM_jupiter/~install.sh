sudo rmmod openvswitch
sudo make install
sudo make modules_install
sudo modprobe openvswitch
sudo /etc/init.d/openvswitch
sleep 5
sudo ovs-vsctl del-br s2
sudo ovs-vsctl add-br s2
sudo ovs-vsctl add-port s2 eth0
sudo ovs-vsctl add-port s2 eth1
sudo ovs-vsctl add-port s2 eth3 
sleep 5
sudo reboot
