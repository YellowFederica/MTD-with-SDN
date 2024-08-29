# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import array
import sys
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib.packet import vlan, ether_types
import random
import re
import sys

honeypots_vlan = 400
port_vlan = {1:{1:[100,200,honeypots_vlan],2:[None],3:[100],4:[100],5:[200],6:[200], 7:[honeypots_vlan],8:[honeypots_vlan]}} # port_vlan[id_switch][numero_porta] => Lista ID VLAN, l'id dello switch è dato dall'ordine di istanziazione
access = {1:[2,3,4,5,6,7,8]} #Porte alle quali sono connessi dispositivi che non usano le VLAN (untagged) come i PC
trunk = {1:[1]} #Porte trunk usate dai dispositivi che capiscono le VLAN (untagged) come switch e router

class SwitchVLANSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SwitchVLANSnort, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.honeypots = {
            "heralding": {
                'ip':'10.0.255.2',
                'mac':'00:00:00:00:00:02',
                'port': 7,
                'busy_services': [],
                'snort_sids': {

                    1004: {
                        'reverse': False,
                        'service': 'ssh'
                    },
                    1005: {
                        'reverse': False,
                        'service': 'ftp'
                    },
                    1006: {
                        'reverse': True,
                        'service': 'ftp'
                    }
                },
                
                'protected_routes': dict()
            },
            "dionaea": {
                'ip':'10.0.255.3',
                'mac':'00:00:00:00:00:03',
                'port': 8,
                'busy_services': [],
                'snort_sids': {
                    1000: {
                        'reverse': False,
                        'service': 'all'
                    },
                    1001: {
                        'reverse': False,
                        'service': 'all'
                    },
                    1002: {
                        'reverse': False,
                        'service': 'all'
                    },
                    1003: {
                        'reverse': False,
                        'service': 'all'
                    },
                    1005: {
                        'reverse': False,
                        'service': 'ftp'
                    },
                    1006: {
                        'reverse': True,
                        'service': 'ftp'
                    }
                },                
                'protected_routes': dict()
            }
        }
        self.snort = kwargs['snortlib']
        self.snort_port = 2 #Porta di Snort si intende sullo switch 1
        self.mac_to_port = {}

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    #Funzione che prende in ingresso il dpid dello switch e la porta in ingresso e restituisce le porte trunk e access
    def vlan_members(self,dpid,in_port,src_vlan):

        B = []
        self.access_ports = []
        self.trunk_ports = []

        if src_vlan == None:
            return

        for item in port_vlan[dpid]: 
            vlans = port_vlan[dpid][item]
            if src_vlan in vlans and item != in_port:
                B.append(item)
        
        for port in B:
            if port in access[dpid]:
                self.access_ports.append(port)
            else:
                self.trunk_ports.append(port)

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)
            

        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    
    # Per un pacchetto che arriva da una porta trunk si manda il frame con il tag alle porte trunk e senza tag a quelle access
    def getActionsArrayTrunk(self,out_port_access,out_port_trunk, parser): 
        actions = []

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))
        
        actions.append(parser.OFPActionPopVlan())#Toglie header 802.1q

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))
        return actions

    #Per un pacchetto da una porta access (che arriva senza tag ma sullo switch è assegnato a una vlan) si manda il pacchetto a tutte le porte
    #access e sulle porte trunk con un VID.
    def getActionsArrayAccess(self,out_port_access,out_port_trunk,src_vlan, parser):
        actions= [ ]       

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))
        
        actions.append(parser.OFPActionPushVlan(33024)) #Aggiunge header 802.1q
        actions.append(parser.OFPActionSetField(vlan_vid=(0x1000|src_vlan)))

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))
        return actions


    #Se il frame in ingresso è untagged allora viene inviato a tutte le porte senza vlan e nelle porte trunk
    def getActionsNormalUntagged(self,dpid,in_port,parser):
        actions= [ ]

        for port in port_vlan[dpid]:
            if port_vlan[dpid][port][0]==None and port!=in_port:
                actions.append(parser.OFPActionOutput(port))
            

        if dpid in trunk:
        
            for port in trunk[dpid]:
                if port!=in_port:
                    actions.append(parser.OFPActionOutput(port))

        return actions


    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg

        alertmsg = msg.alertmsg[0].decode('utf-8')
        sid = re.search(r'\[(.*?)\]',alertmsg).group(1)
        print(f"sid: {sid}. msg: {alertmsg}")

        pkt = msg.pkt
        #self.packet_print(pkt)
        pkt = packet.Packet(array.array('B', pkt))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        ip_v4 = pkt.get_protocol(ipv4.ipv4)
        attacker_ip = ip_v4.src
        victim_ip = ip_v4.dst
        victim_mac = eth.dst

    # Verifica se l'attaccante è un honeypot
        from_honeypot = any(attacker_ip == pot['ip'] for pot in self.honeypots.values())
        if from_honeypot:
            print("From honeypot. Returning")
            sys.stdout.flush()
            return

        print(f"src ip: {attacker_ip}, dst ip: {victim_ip}")
        sys.stdout.flush()

        # Trova il potenziale honeypot per il sid dato
        dst_pot = None
        already_reversed = False
        for pot in self.honeypots.values():
            if int(sid) in pot['snort_sids']:
                pot_sid = pot['snort_sids'][int(sid)]
                print(f"Found sid {sid}")
                sys.stdout.flush()

                if pot_sid['reverse'] and not already_reversed:
                    print("Reversing attacker and victim")
                    sys.stdout.flush()
                    victim_ip, attacker_ip = attacker_ip, victim_ip
                    victim_mac = eth.src
                    already_reversed= True
                    print(f"attacker ip: {attacker_ip}, victim ip: {victim_ip}")
                    print(f"victim mac: {victim_mac}")
                    sys.stdout.flush()

                if pot_sid['service'] in pot['busy_services'] or 'all' in pot['busy_services']:
                    print("Honeypot Busy. Checking next honeypot...")
                    sys.stdout.flush()
                    continue


                dst_pot = pot
                break



        # Verifica se l'attaccante è già assegnato a un honeypot
        for pot in self.honeypots.values():
            if attacker_ip in pot['protected_routes']:
                print("Attacker already on a honeypot. Returning.")
                sys.stdout.flush()
                return

        # Prevenzione dell'inversione causata da un router
        if victim_ip in dst_pot['protected_routes']:
            print("Protected route inversion. Returning.")
            sys.stdout.flush()
            return

        # Aggiorna i percorsi protetti e i servizi occupati
        if attacker_ip not in dst_pot['protected_routes']:
            dst_pot['protected_routes'][attacker_ip] = set()
        dst_pot['protected_routes'][attacker_ip].add(victim_ip)

        dst_pot['busy_services'].append(pot_sid['service'])
        sys.stdout.flush()

        if dst_pot == None:
            print("No appropriate honeypot found. Setting drop action.")
            sys.stdout.flush()
            for datapath in self.datapaths.values():
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                port_victim = self.mac_to_port[datapath.id][victim_mac] #Serve per emulare la VLAN del client legittimo (è la soluzione più rapida per far sì che non ci siano problemi di gateway ecc.)
                vlan_victim = port_vlan[datapath.id][port_victim][0]

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,vlan_vid=vlan_victim|ofproto_v1_3.OFPVID_PRESENT,ipv4_src=attacker_ip, ipv4_dst=victim_ip)
                actions = []  
                self.add_flow(datapath, 103, match, actions)
          
            return
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            port_victim = self.mac_to_port[datapath.id][victim_mac] #Serve per emulare la VLAN del client legittimo (è la soluzione più rapida per far sì che non ci siano problemi di gateway ecc.)
            vlan_victim = port_vlan[datapath.id][port_victim][0]

            print("Setting atk -> honeypot")
            # ATTACKER -> HONEYPOT
            #Match dei pacchetti con vlan_vid = vlan_victim e ip_src = attacker_ip e ip_dst = victim_ip
            #Action: setta ip_dst = dst_pot["ip"] e mac_dst = dst_pot["mac"] e porta di output = dst_pot["port"]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,vlan_vid=vlan_victim|ofproto_v1_3.OFPVID_PRESENT,ipv4_src=attacker_ip, ipv4_dst=victim_ip)
            actions = []
            actions = [
                parser.OFPActionSetField(ipv4_dst=dst_pot["ip"]),
                parser.OFPActionSetField(eth_dst=dst_pot["mac"]),
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(dst_pot["port"])
                ]
            self.add_flow(datapath, 102, match, actions)
            
            print("Setting honeypot -> atk")
            #HONEYPOT -> ATTACKER
            parser = datapath.ofproto_parser
            self.vlan_members(datapath.id,port_victim,vlan_victim)
            #Match dei pacchetti con ip_src = dst_pot["ip"] e ip_dst = attacker_ip
            #Action: setta ip_src = victim_ip e mac_src = victim_mac e porta di output = 1
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=dst_pot["ip"], ipv4_dst=attacker_ip)
            actions = [
                parser.OFPActionSetField(eth_src = victim_mac),
                parser.OFPActionSetField(ipv4_src = victim_ip),
                parser.OFPActionOutput(1)
                ]
            self.add_flow(datapath, 101, match, actions)
            print("Rules setted")
            sys.stdout.flush()
        sys.stdout.flush()


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
            vlan_header_present = True
            vlan_header = pkt.get_protocol(vlan.vlan)
            src_vlan = vlan_header.vid
        elif dpid not in port_vlan: #Controllo se lo switch è configurato per usare le vlan
            vlan_header_present = False
            in_port_type = "NORMAL SWITCH"
            src_vlan = None
        elif port_vlan[dpid][in_port][0]== " " or in_port in trunk[dpid]: #path untagged
            vlan_header_present = False
            in_port_type = "NORMAL UNTAGGED"
            src_vlan = None 
        else:
            vlan_header_present = False
            src_vlan=port_vlan[dpid][in_port][0]
            
        print(f"Packet from VLAN {src_vlan}")

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.vlan_members(dpid, in_port, src_vlan)
        out_port_type = " "

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port


        if dst in self.mac_to_port[dpid]:
            out_port_known = True
            out_port = self.mac_to_port[dpid][dst]
            
            if src_vlan != None:
                if out_port in access[dpid]:
                    out_port_type = "ACCESS"
                else:
                    out_port_type = "TRUNK"
            else:
                out_port_type = "NORMAL"
        else:
            out_port_known = False
            out_port_access = self.access_ports
            out_port_trunk = self.trunk_ports
        

        if out_port_known == True:
            if vlan_header_present and out_port_type == "ACCESS":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan)) #OR tra 4096 che è il l'id massimo delle vlan e la source vlan
                actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(out_port)] #Tolgo header vlan visto che il pc connesso non è a conoscenza delle vlan
            elif vlan_header_present and out_port_type == "TRUNK": #Se c'è il vlan header lo mando banalmente alla porta trunk in uscita
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionOutput(out_port)]
            elif not vlan_header_present and out_port_type == "TRUNK": #Se non c'è il vlan header lo aggiungo
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid = (0x1000 | src_vlan)),parser.OFPActionOutput(out_port)]
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]

            if not any(in_port == pot['port'] for pot in self.honeypots.values()):
                actions.append(parser.OFPActionOutput(self.snort_port)) #Aggiungo port mirroring per snort

            if msg.buffer_id != ofproto.OFP_NO_BUFFER: #Aggiungo la entry del flusso nello switch
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
            
        else:
            if vlan_header_present:
                actions = self.getActionsArrayTrunk(out_port_access, out_port_trunk, parser)
            elif src_vlan != None:
                actions = self.getActionsArrayAccess(out_port_access, out_port_trunk, src_vlan, parser)
            elif in_port_type == "NORMAL UNTAGGED":
                actions = self.getActionsNormalUntagged(dpid, in_port, parser)
            else:
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            
            if not any(in_port == pot['port'] for pot in self.honeypots.values()):
                actions.append(parser.OFPActionOutput(self.snort_port)) #Aggiungo port mirroring per snort

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
