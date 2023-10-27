#!/usr/bin/env python3

import yaml
import subprocess
import tempfile
import queue
import signal
from collections import namedtuple
import time
import socket
import netifaces
import logging
import ipaddress
from scapy.all import sendp, sniff
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
import threading
from pathlib import *

default_config_path = Path('/usr/local/etc/rt-bridge.yaml')

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
    mac = linklocal_to_mac(linklocal)
    return IfInfo(mac, linklocal)

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

class Handler:

    def __init__(self):
        self.handlers = {}
    
    def add_handler(self, icmp6_type, handler):
        if icmp6_type in self.handlers:
            raise Exception()
        self.handlers[icmp6_type] = handler

    def handle(self, pkt):
        if pkt.type == 2054:
#            pkt.show()
            return
        icmp6_type = pkt.payload.payload.type
        if icmp6_type in self.handlers:
            self.handlers[icmp6_type](pkt)
            return
        logging.debug(f'unhandled packet: icmp6.type={icmp6_type}')

# if we don't have an RA, or we have a stale one (older than 60 seconds),
# solicit every 5 seconds, only call script if ra has changed
def invoke_rtadv_script(config, rtadv):
    ndra = rtadv.getlayer(2)
    with tempfile.NamedTemporaryFile(mode='w+') as stream:
        stream.write(json.dumps(ndra, cls=ICMPv6JSONEncoder))
        stream.flush()
        try:
            subprocess.run([config['ra_script'], stream.name])
        except Exception as e:
            logging.exception(e)
        
def rt_solicitor(context, finish, sniffer):
    logging.info('start r_solicitor')
    rtsol_if = config['north_if']
    rtsol_if_info = get_if_info(rtsol_if)

    rtsol = Ether(src=rtsol_if_info.mac, dst=ipv6mcast_02.mac)
    rtsol /= IPv6(src=rtsol_if_info.addr, dst=ipv6mcast_02.addr)
#    north_rt_mac = linklocal_to_mac(ipaddress.ip_address(config['north_rt_addr']))
#    ipv6mcast_02
#    rtsol = Ether(src=rtsol_if_info.mac, dst=north_rt_mac)
#    rtsol /= IPv6(src=rtsol_if_info.addr, dst=config['north_rt_addr'])
    rtsol /= ICMPv6ND_RS()
    rtsol /= ICMPv6NDOptSrcLLAddr(lladdr=rtsol_if_info.mac)
    rtsol = rtsol.build()

    q = queue.Queue()
    def handler(pkt):
        if pkt.sniffed_on != rtsol_if:
            return False
        q.put(pkt)
    sniffer.add_handler(134, handler)

    last_rtadv_ts = 0
    last_rtadv = None
    while not finish.is_set():
        if (time.time() - last_rtadv_ts) > 60:
            sendp(rtsol, iface=rtsol_if, verbose=True)
        try:
            rtadv = q.get(True, timeout=5)
        except queue.Empty:
            continue
        north_rt_info = IfInfo(rtadv.src, rtadv.getlayer(1).src)
        context.set_north_rt_info(north_rt_info)
        send_rtadv(context)
        last_rtadv_ts = time.time()
        if last_rtadv != rtadv:
            invoke_rtadv_script(context.config, rtadv)
            last_rtadv = rtadv

# simply bounce the solicitations back to the sender
# with an advertisement
def simple_nbrsol_handler(context, finish, sniffer):
    logging.info('start simple_nbrsol_handler')

    nbrsol_q = queue.Queue()
    def nbrsol_handler(pkt):
        if pkt.sniffed_on != context.config['north_if']:
            return False
        nbrsol_q.put(pkt)
    sniffer.add_handler(135, nbrsol_handler)

    while not finish.is_set():
        try:
            nbrsol = nbrsol_q.get(True, timeout=1)
        except queue.Empty:
            continue
        north_rt_info = context.get_north_rt_info()
        south_rt_info = context.get_south_rt_info()
        if (north_rt_info is None) or (south_rt_info is None):
            continue
        if nbrsol.getlayer(1).src != north_rt_info.addr:
            continue
        tgt = ipaddress.ip_address(nbrsol.getlayer(2).tgt)
        if not tgt.is_global:
            continue
        nbradv = Ether(src=south_rt_info.mac, dst=nbrsol.src)
        nbradv /= IPv6(src=south_rt_info.addr, dst=nbrsol.getlayer(1).src)
        nbradv /= ICMPv6ND_NA(R=1, S=1, O=1, tgt=tgt)
        nbradv /= ICMPv6NDOptDstLLAddr(lladdr=south_rt_info.mac)
        nbradv = nbradv.build()
        logging.info(f'sending nbradv for {tgt}')
        sendp(nbradv, iface=context.config['north_if'], verbose=True)

#def nbrsol_handler(config, finish, sniffer):
#    logging.info('start nbrsol_handler')
#
#    nbrsol_q = queue.Queue()
#    def nbrsol_handler(pkt):
#        if pkt.sniffed_on != config['north_if']:
#            return False
#        if pkt.getlayer(1).src != config['north_rt_addr']:
#            return False
#        tgt = ipaddress.ip_address(pkt.getlayer(2).tgt)
#        if not tgt.is_global:
#            return False
#        nbrsol_q.put(pkt)
#    sniffer.add_handler(135, nbrsol_handler)
#
#    lan_if_info = get_if_info(config['lan_if'])
#    while not finish.is_set():
#        try:
#            nbrsol = nbrsol_q.get(True, timeout=1)
#        except queue.Empty:
#            continue
#        # send a solicitation on the lan interface, wait
#        # for that specific response, ignore all others, ignore
#        # after 5 seconds
#        tgt = ipaddress.ip_address(nbrsol.getlayer(2).tgt)
#        lan_nbrsol = Ether(src=lan_if_info.mac, dst=nbrsol.dst)
#        lan_nbrsol /= IPv6(src=lan_if_info.addr, dst=nbrsol.getlayer(1).dst)
#        lan_nbrsol /= ICMPv6ND_NS(tgt=tgt)
#        lan_nbrsol /= ICMPv6NDOptSrcLLAddr(lladdr=lan_if_info.mac)
#        lan_nbrsol = lan_nbrsol.build()
#        sendp(lan_nbrsol, iface=config['lan_if'], verbose=True)
#
#def nbradv_handler(config, finish, sniffer):
#    logging.info('start nbradv_handler')
#
#    lan_nbradv_q = queue.Queue()
#    def nbradv_handler(pkt):
#        if pkt.sniffed_on != config['lan_if']:
#            return False
#        tgt = ipaddress.ip_address(pkt.getlayer(2).tgt)
#        if not tgt.is_global:
#            return False
#        lan_nbradv_q.put(pkt)
#    sniffer.add_handler(136, nbradv_handler)
#
#    south_rt_mac = linklocal_to_mac(ipaddress.ip_address(config['south_rt_addr']))
#    north_rt_mac = linklocal_to_mac(ipaddress.ip_address(config['north_rt_addr']))
#
#    while not finish.is_set():
#        try:
#            lan_nbradv = lan_nbradv_q.get(True, timeout=1)
#        except queue.Empty:
#            continue
#        tgt = lan_nbradv.getlayer(2).tgt
#        nbradv = Ether(src=south_rt_mac, dst=north_rt_mac)
#        nbradv /= IPv6(src=config['south_rt_addr'], dst=config['north_rt_addr'])
#        nbradv /= ICMPv6ND_NA(R=1, S=1, O=1, tgt=tgt)
#        nbradv /= ICMPv6NDOptDstLLAddr(lladdr=south_rt_mac)
#        nbradv = nbradv.build()
#        sendp(nbradv, iface=config['north_if'], verbose=True)

def send_rtadv(context):
    north_rt_info = context.get_north_rt_info()
    south_rt_info = context.get_south_rt_info()
    if (north_rt_info is None) or (south_rt_info is None):
        return
    rtadv = Ether(src=north_rt_info.mac, dst=south_rt_info.mac)
    rtadv /= IPv6(src=north_rt_info.addr, dst=south_rt_info.addr)
    rtadv /= ICMPv6ND_RA(routerlifetime=300)
    rtadv /= ICMPv6NDOptSrcLLAddr(lladdr=north_rt_info.mac)
    rtadv = rtadv.build()
    sendp(rtadv, iface=config['south_if'], verbose=True)

# respond to rtsols
def rtsol_handler(context, finish, sniffer):
    logging.info('start rtsol_handler')

    rtsol_q = queue.Queue()
    def rtsol_handler(pkt):
        if pkt.sniffed_on != context.config['south_if']:
            return False
        rtsol_q.put(pkt)
    sniffer.add_handler(133, rtsol_handler)

    while not finish.is_set():
        try:
            rtsol = rtsol_q.get(True, timeout=1)
        except queue.Empty:
            continue
        south_rt_info = IfInfo(rtsol.src, rtsol.getlayer(1).src)
        context.set_south_rt_info(south_rt_info)
        send_rtadv(context)

# send a rtadv out every 60 seconds
def rt_advertiser(context, finish):
    logging.info('start rt_advertiser')
    while not finish.is_set():
        send_rtadv(context)
        finish.wait(timeout=60)

def sniffer(config, finish, handler):
    logging.info("start sniffer")
    ip6filter = "arp or (icmp6 and (" \
        "ip6[40] == 133 or ip6[40] == 134 " \
        "or ip6[40] == 135 or ip6[40] == 136))"
    sniff(store=0, iface=[config['north_if'], config['south_if'], config['lan_if']], filter=ip6filter, prn=handler.handle, stop_filter=lambda x: finish.is_set())

# 133 = rtsol, 134 = rtadv, 135 = nbrsol, 136 = nbradv

class Context:

    def __init__(self, config):
        self.config = config
        self.north_rt_info = None
        self.south_rt_info = None

    def get_north_rt_info(self):
        return self.north_rt_info

    def set_north_rt_info(self, north_rt_info):
        logging.info(f'set_north_rt_info: {north_rt_info}')
        self.north_rt_info = north_rt_info

    def get_south_rt_info(self):
        return self.south_rt_info

    def set_south_rt_info(self, south_rt_info):
        logging.info(f'set_south_rt_info: {south_rt_info}')
        self.south_rt_info = south_rt_info

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    config = yaml.load(default_config_path.read_text(), yaml.FullLoader)
    context = Context(config)

    finish = threading.Event()

    def signal_handler(*_):
        finish.set()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    handler = Handler()

    sniffer_t = threading.Thread(target=sniffer, args=(config, finish, handler,))
    sniffer_t.start()

    rt_solicitor_t = threading.Thread(target=rt_solicitor, args=(context, finish, handler,))
    rt_solicitor_t.start()

#    nbrsol_handler_t = threading.Thread(target=nbrsol_handler, args=(config, finish, handler,))
#    nbrsol_handler_t.start()

#    nbradv_handler_t = threading.Thread(target=nbradv_handler, args=(config, finish, handler,))
#    nbradv_handler_t.start()

    simple_nbrsol_handler_t = threading.Thread(target=simple_nbrsol_handler, args=(context, finish, handler,))
    simple_nbrsol_handler_t.start()

    rtsol_handler_t = threading.Thread(target=rtsol_handler, args=(context, finish, handler,))
    rtsol_handler_t.start()

    rt_advertiser_t = threading.Thread(target=rt_advertiser, args=(context, finish,))
    rt_advertiser_t.start()

    finish.wait()

    sniffer_t.join()
    rt_solicitor_t.join()
#    nbrsol_handler_t.join()
#    nbradv_handler_t.join()
    simple_nbrsol_handler_t.join()
    rtsol_handler_t.join()
    rt_advertiser_t.join()

