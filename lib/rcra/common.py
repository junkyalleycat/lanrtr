#!/usr/bin/env python3

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

IfInfo = namedtuple('IfInfo', ['mac', 'addr'])

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

def get_if_info(ifname):
    addrs = netifaces.ifaddresses(ifname)
    lladdr, = addrs[netifaces.AF_LINK]
    lladdr = lladdr['addr']
    linklocal = None
    for inet6addr in addrs[netifaces.AF_INET6]:
        addr = inet6addr['addr']
        if '%' in addr:
            addr = addr.split('%')[0]
        inet6addr = ipaddress.ip_address(addr)
        if inet6addr.is_link_local:
            linklocal = inet6addr
            break
    if linklocal is None:
        raise Exception()
    return IfInfo(lladdr, linklocal)

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

