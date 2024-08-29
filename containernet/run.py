from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
import os

def set_network(h, vlan = None, ip ='0.0.0.0/32', gw = '0.0.0.0' ):
        intf = h.defaultIntf()
        if vlan != None:
            h.cmd( f"ip link add link {intf} name {intf}.{vlan} type vlan id {vlan}" )
            h.cmd( f"ip addr add {ip} dev {intf}.{vlan}" )
            h.cmd( f"ip link set dev {intf} up" )
            h.cmd( f"ip link set dev {intf}.{vlan} up" )
            h.cmd("ip route flush 0/0")
            if gw != "0.0.0.0":
                h.cmd(f"ip route add default via {gw} dev {intf}.{vlan}")
            h.cmd(f"ifconfig {intf}.{vlan} up")
        else:
#            h.cmd( f"ip addr add {ip} dev {intf}" )
            h.cmd( f"ip link set dev {intf} up" )
            h.cmd("ip route flush 0/0")
            if gw != "0.0.0.0":
                h.cmd(f"ip route add default via {gw} dev {intf}")
                print(f"ip route add default via {gw} dev {intf}")
                print("Aggiunto gateway")


setLogLevel('info')

net = Containernet(controller=RemoteController)
info('*** Adding docker containers\n')
#Immagine docker del controller del router
c0_docker = net.addDocker(
                        name='c0_docker',
                        ip='10.0.5.1/30',
                        dimage="mtd/ryu",
                        volumes=[os.environ["VM_PATH"]+"/ryu/controllers:/controllers"],
                        ports= [6633,51234],
                        port_bindings={6633: 6633,51234:51234}
                    )
c1_docker = net.addDocker(
                        name='c1_docker',
                        ip='10.2.5.1/30',
                        dimage="mtd/ryu",
                        volumes=[os.environ["VM_PATH"]+"/ryu/controllers:/controllers"],
                        ports= [6633],
                        port_bindings={6633:6634}
                    )


info('*** Adding controller\n')
#Controller del router
c0 = net.addController(
                        name='c0',
                        controller=RemoteController,
                        ip='192.168.199.2',
                        protocol='tcp',
                        port=6633,
                    )
c1 = net.addController(
                        name='c1',
                        controller=RemoteController,
                        ip='192.168.199.2',
                        protocol='tcp',
                        port=6634,
                    )

ids = net.addDocker(
                        name='ids',
                        ip='10.0.2.1/24',
                        dimage="mtd/snort",
                        volumes= [os.environ["VM_PATH"]+"/snort/rules:/etc/snort/rules"]
                    )
r1 = net.addDocker(name='r1',
                    ip='10.0.0.1/24',
                    dimage="mtd/frr",
                    volumes=[os.environ["VM_PATH"]+"/frr:/etc/frr","/lib/modules:/lib/modules" ],
                    cap_add = ["sys_admin", "mknod"])
#Rete privata
pc1 = net.addDocker('pc1', ip='10.0.0.2/24', dimage="mtd/ubuntu")
pc2 = net.addDocker('pc2', ip='10.0.0.3/24', dimage="mtd/ubuntu")
#DMZ
ftp = net.addDocker('ftp', ip='10.0.1.2/24', dimage="anoopyadavan5237/vsftp2.3.4:v1")
ftp.cmd("apt update")
ftp.cmd("apt install vlan net-tools ethtool iproute2 iputils-ping traceroute -y")
dmz2 = net.addDocker('dmz2', ip='10.0.1.3/24', dimage="mtd/ubuntu")

#Attackers
atk1 = net.addDocker('atk1', ip='10.1.0.2/24', dimage="metasploitframework/metasploit-framework",volumes=[os.environ["VM_PATH"]+"/bruteforce:/bruteforce" ])
atk2 = net.addDocker('atk2', ip='10.1.0.3/24', dimage="metasploitframework/metasploit-framework",volumes=[os.environ["VM_PATH"]+"/bruteforce:/bruteforce" ])

#Honeypots
heralding = net.addDocker(name='heralding',
                            ip='10.0.255.2/24',
                            mac="00:00:00:00:00:02",
                            volumes=[os.environ["VM_PATH"]+"/honeypots/logs/heralding:/logs"],
                            dimage="heralding")
dionaea = net.addDocker(name='dionaea',
                        ip='10.0.255.3/24',
                        mac="00:00:00:00:00:03",
                        volumes=[os.environ["VM_PATH"]+"/honeypots/logs/:/opt/dionaea/var/log",
                                 os.environ["VM_PATH"]+"/honeypots/logs/dionaea/data:/opt/dionaea/var/lib/dionaea",
                                 os.environ["VM_PATH"]+"/dionaea/config:/opt/dionaea/etc/dionaea"
                                 ],
                        dimage="mtd/dionaea", cap_add = ["sys_admin", "mknod"],ports= [21])

info('*** Creating links\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')

net.addLink(r1,s1, port1=0, port2=1)
r1.cmd("sudo ifconfig r1-eth0 10.0.13.254/24") #FRR non esegue come root quindi va settata manualmente l'interfaccia
net.addLink(ids, s1, port1=0, port2=2)
net.addLink(ids,c0_docker, params1={'ip' : '10.0.5.2/30' },params2={'ip' : '10.0.5.1/30' }) #Link privato tra Snort e Ryu
net.addLink(pc1, s1, port2 = 3)
net.addLink(pc2, s1, port2=4)
net.addLink(ftp,s1, port2=5)
net.addLink(dmz2,s1,port2=6)
net.addLink(heralding,s1, port2=7)
net.addLink(dionaea,s1, port2=8)
net.addLink(r1, s2,port1=1, port2=1)
net.addLink(atk1, s2,port2=2)
net.addLink(atk2, s2,port2=3)

set_network(r1,100,ip='10.0.0.1/24')
set_network(r1,200,ip='10.0.1.1/24')
set_network(r1,400,ip='10.0.255.1/24')
set_network(r1,ip='10.1.0.1/24')

info('*** Starting network\n')
net.build()
s1.start([c0])
s2.start([c1])

set_network(atk2,ip='10.1.0.3/24',gw='10.1.0.1')
set_network(pc1,None,ip='10.0.0.2/24', gw='10.0.0.1')
set_network(pc2,None,ip='10.0.0.3/24', gw='10.0.0.1')
set_network(ftp,None,ip='10.0.1.2/24', gw='10.0.1.1')
set_network(dmz2,None,ip='10.0.1.3/24', gw='10.0.1.1')
set_network(heralding,None,ip='10.0.255.2/24', gw='10.0.255.1')
set_network(dionaea,None,ip='10.0.255.3/24', gw='10.0.255.1')
set_network(atk1,ip='10.1.0.2/24',gw='10.1.0.1')

print("Launching Ryu controllers")
c0_docker.cmd("nohup ryu-manager /controllers/simple_switch_snort.py > /controllers/logs/log_s1.txt &")
c1_docker.cmd("nohup ryu-manager /controllers/simple_switch_13.py > /controllers/logs/log_s2.txt &")

print("Starting services")
ftp.cmd("nohup vsftpd &")
ftp.cmd("service vsftpd restart")
print("Starting IDS")
ids.cmd("sleep 3") #Attesa avvio controller
ids.cmd("nohup sh entrypoint.sh &")
print("Starting Honeypots")
heralding.cmd("cd /logs")
heralding.cmd("nohup heralding -l /logs/heralding.log &")
dionaea.cmd("nohup sh /usr/local/sbin/entrypoint.sh &")
print("Restarting Router")
r1.cmd("service frr restart")

info('*** Running CLI\n')
CLI(net)

info('*** Stopping network')
net.stop()



