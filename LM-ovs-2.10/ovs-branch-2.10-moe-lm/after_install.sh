#!/bin/bash

sudo mkdir --parent /usr/local/etc/openvswitch
sudo mkdir --parent /usr/local/share/openvswitch
sudo mkdir --parent /usr/local/var/run/openvswitch
sudo mkdir --parent /usr/local/var/log/openvswitch/
sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db /usr/local/share/openvswitch/vswitch.ovsschema

sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
--remote=db:Open_vSwitch,Open_vSwitch,manager_options \
--private-key=db:Open_vSwitch,SSL,private_key \
--certificate=db:Open_vSwitch,SSL,certificate \
--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
--no-self-confinement \
--pidfile --detach --log-file
