#!/usr/bin/env python3

import asyncio
import threading
from scapy.all import sniff
from collections import namedtuple
import netifaces
import ipaddress
from scapy.all import NoPayload
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.inet6 import ICMPv6ND_RS
from scapy.layers.inet6 import ICMPv6ND_RA
from scapy.layers.inet6 import ICMPv6ND_NS
from scapy.layers.inet6 import ICMPv6ND_NA
from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo
from scapy.layers.inet6 import ICMPv6NDOptRDNSS
from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
import json

IPv6MCast = namedtuple('IPv6MCast', ['mac', 'addr'])
# all nodes
ipv6mcast_01 = IPv6MCast('33:33:00:00:00:01', ipaddress.ip_address('ff02::1'))
# all routers
ipv6mcast_02 = IPv6MCast('33:33:00:00:00:02', ipaddress.ip_address('ff02::2'))

IfAddrs = namedtuple('IfAddrs', ['lladdr', 'linklocal', 'gaddrs'])
class IfAddrs2(namedtuple('IfAddrs', ['link_layers', 'link_locals', 'globals'])):

    @property
    def link_layer(self):
        link_layer, = self.link_layers
        return link_layer

    @property
    def link_local(self):
        link_local, = self.link_locals
        return link_local

def linklocal_to_mac(linklocal):
    assert linklocal.is_link_local

    ipv6 = linklocal.exploded
    if '%' in ipv6:
        ipv6 = ipv6.split('%')[0]

    mac_parts = [None]*6
    ipv6_parts = ipv6.split(':')
    mac_parts[0] = ipv6_parts[4][0:2]
    mac_parts[0] = "%02x" % (int(mac_parts[0], 16) ^ 2)
    mac_parts[1] = ipv6_parts[4][2:4]
    mac_parts[2] = ipv6_parts[5][0:2]
    mac_parts[3] = ipv6_parts[6][2:4]
    mac_parts[4] = ipv6_parts[7][0:2]
    mac_parts[5] = ipv6_parts[7][2:4]
    return ':'.join(mac_parts)

def get_if_addrs(ifname):
    addrs = netifaces.ifaddresses(ifname)
    link_layers = []
    for link in addrs[netifaces.AF_LINK]:
        link_layers.append(link['addr']) 
    link_layer, = link_layers
    link_locals = []
    globals_ = []
    for inet6 in addrs[netifaces.AF_INET6]:
        inet6_addr = inet6['addr']
        if '%' in inet6_addr:
            inet6_addr = inet6_addr.split('%')[0]
        inet6_addr = ipaddress.ip_address(inet6_addr)
        if inet6_addr.is_link_local:
            link_locals.append(inet6_addr)
        elif inet6_addr.is_global:
            globals_.append(inet6_addr)
    link_layer, = link_layers
    link_local, = link_locals
    return IfAddrs(link_layer, link_local, globals_)

class ICMPv6JSONEncoder(json.JSONEncoder):

    def encode_layer(self, layer):
        o = {}
        for f in layer.fields:
            o[f] = getattr(layer, f) #json.JSONEncoder.default(self, getattr(layer, f))
        payload = layer.payload
        if type(payload) is not NoPayload:
            if 'payload' in o:
                raise Exception()
            o['payload'] = self.default(layer.payload) #json.JSONEncoder.default(self, layer.payload)
        return o

    def default(self, obj):
        if type(obj) is ICMPv6ND_RA:
            o = {}
            for field_name in obj.fields:
                o[field_name] = getattr(obj, field_name)
            o['options'] = []
            for i in range(1, len(obj.layers())):
                layer = obj.getlayer(i)
                o['options'].append(self.default(layer))
            return o
        elif type(obj) in [ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, ICMPv6NDOptSrcLLAddr]:
            o = {}
            for field_name in obj.fields:
                o[field_name] = getattr(obj, field_name)
            return o
        return json.JSONEncoder.default(self, obj)

async def sniffer(if_names, pfilter, pkt_handler):
    loop = asyncio.get_event_loop()

    class SnifferThread(threading.Thread):

        def __init__(self):
            super().__init__(daemon=True)
            self.run_s = threading.Event()
            self.run_e = None

        def run(self):

            def prn(pkt):
                if not self.run_s.is_set():
                    loop.call_soon_threadsafe(pkt_handler, pkt)

            def sfilter(pkt):
                return self.run_s.is_set()

            try:
                sniff(store=0, iface=if_names, filter=pfilter, prn=prn, stop_filter=sfilter)
            except BaseException as e:
                self.run_e = e

        def stop(self):
            self.run_s.set()

        def join(self):
            while self.is_alive():
                if self.run_s.wait(timeout=1):
                    break
            if self.run_e is not None:
                raise self.run_e

    sniffer_th = SnifferThread()
    sniffer_th.start()
    try:
        await asyncio.get_event_loop().run_in_executor(None, sniffer_th.join)
    finally:
        sniffer_th.stop()

