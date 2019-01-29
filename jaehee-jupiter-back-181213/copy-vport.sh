#!/bin/bash
sudo cp vport.c ./ovs-master/openvswitch-2.3.1_somo/datapath/
sudo cp vport.c ./ovs-master/openvswitch-2.3.1_somo/datapath/linux
scp vport.c wins@earth:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/
scp vport.c wins@earth:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/linux/
scp vport.c wins@moon:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/
scp vport.c wins@moon:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/linux/
scp vport.c wins@mars:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/
scp vport.c wins@mars:/home/wins/jaehee/ovs-master/openvswitch-2.3.1_somo/datapath/linux/

