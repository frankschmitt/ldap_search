#!/usr/bin/env bash

# Author: m8r0wn
# Description: ldap_search setup script, installs Impacket for python36 from github

echo -e "[*] Installing Impacket library for Python 3.6"
# load submodule
git submodule init
git submodule update

# Temp solution until Impacket v.0.9.18 released with Python3 support - I know it's messy
cd impacket
python3 setup.py install
mv impacket ../impacket36
mv impacket.egg-info ../
cd ../
rm -rf impacket
mv impacket36 impacket

echo -e "\n[*] ldap_search setup complete\n\n"
