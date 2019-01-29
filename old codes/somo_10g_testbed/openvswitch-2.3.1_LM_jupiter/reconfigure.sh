#!/bin/bash
sudo ovs-vsctl del-br s6
sudo ovs-vsctl add-br s6
sudo ovs-vsctl add-port s6 p1p1
sudo ovs-vsctl add-port s6 p1p2
sudo ovs-vsctl add-port s6 p4p1
sudo reboot
