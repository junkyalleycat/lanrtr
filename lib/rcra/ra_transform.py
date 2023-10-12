#!/usr/bin/env python3

import netifaces
import logging
import ipaddress
import code
from scapy.all import sendp, sniff
from scapy.layers.inet6 import ICMPv6ND_RA
from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
from scapy.layers.inet6 import ICMPv6NDOptRDNSS
from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo
from scapy.layers.inet6 import ICMPv6NDOptDNSSL
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

def phx(array_alpha):
    return ''.join('{:02x}'.format(x) for x in array_alpha)

# TODO ghetto scapy, is there a better way?
def get_hdr_bytes(pkt):
    b_pkt = bytes(pkt)
    return b_pkt[:len(b_pkt)-len(pkt.payload)]

def get_link_local(ifname, *, include_scope=None):
    include_scope = False if include_scope is None else include_scope
    for addr in netifaces.ifaddresses(ifname)[netifaces.AF_INET6]:
        if include_scope:
            aaaa = addr['addr']
        else:
            if '%' in addr['addr']:
                aaaa = addr['addr'].split('%', 1)[0]
            else:
                aaaa = addr['addr']
        addr = ipaddress.ip_address(aaaa) 
        if addr.is_link_local:
            return addr
    return None

class Handler:

    def __init__(self, inject_if, dns_if, dnssl):
        self.inject_if = inject_if
        self.dns_if = dns_if
        self.dnssl = dnssl

    def callback(self, e_pkt): #pkthdr, pkt):
        e_hdr = Ether(get_hdr_bytes(e_pkt))
        ip6_pkt = e_pkt.payload
        ip6_hdr = IPv6(get_hdr_bytes(ip6_pkt))
        del ip6_hdr.plen
        ra_pkt = ip6_pkt.payload
        ra_hdr = ICMPv6ND_RA(get_hdr_bytes(ra_pkt))
        del ra_hdr.cksum
        ra_hdr.routerlifetime = 300
    
        new_pkt = e_hdr / ip6_hdr / ra_hdr
    
        dns_addr = get_link_local(self.dns_if)
        if dns_addr is None:
            raise Exception(f'link local not found: {dns_ifname}')
        
        # grab the global prefixes and the src ll, skip layer 0 (ra_hdr)
        for i in range(1, len(ra_pkt.layers())):
            layer = ra_pkt.getlayer(i)
            layer_bytes = get_hdr_bytes(ra_pkt.getlayer(i))
            if type(layer) == ICMPv6NDOptPrefixInfo:
                new_pkt /= ICMPv6NDOptPrefixInfo(layer_bytes)
            elif type(layer) == ICMPv6NDOptRDNSS:
                if str(dns_addr) in layer.dns:
                    logging.debug('found dnssl signature layer, returning')
                    return
                logging.debug(f'ignoring layer: {layer.__class__}')
            elif type(layer) == ICMPv6NDOptSrcLLAddr:
                new_pkt /= ICMPv6NDOptSrcLLAddr(layer_bytes)
            else:
                logging.debug(f'ignoring layer: {layer.__class__}')
    
        # create a new prefix layer for site local
    #    site_local_prefix = ICMPv6NDOptPrefixInfo(validlifetime=600, preferredlifetime=600, prefix='fd82::', L=1, A=0)
    #    new_pkt /= site_local_prefix
    
        # raincity dns
        new_pkt /= ICMPv6NDOptRDNSS(lifetime=600, dns=[str(dns_addr)])
        new_pkt /= ICMPv6NDOptDNSSL(lifetime=600, searchlist=self.dnssl)
    
        sendp(new_pkt, iface=self.inject_if, verbose=False) #tmnet6')

def main():
    logging.basicConfig(level=logging.INFO)
    callback = Handler('tmnet6', 'lan_bridge', ['lan']).callback
    sniff(iface='tmnet6', filter='icmp6 and ip6[40] = 134', prn=callback)

if __name__ == '__main__':
    main()

