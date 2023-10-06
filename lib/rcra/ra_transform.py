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

def callback(e_pkt): #pkthdr, pkt):
    e_hdr = Ether(get_hdr_bytes(e_pkt))
    ip6_pkt = e_pkt.payload
    ip6_hdr = IPv6(get_hdr_bytes(ip6_pkt))
    del ip6_hdr.plen
    ra_pkt = ip6_pkt.payload
    ra_hdr = ICMPv6ND_RA(get_hdr_bytes(ra_pkt))
    del ra_hdr.cksum
    ra_hdr.routerlifetime = 300

    new_pkt = e_hdr / ip6_hdr / ra_hdr
    
    # grab the global prefixes and the src ll, skip layer 0 (ra_hdr)
    for i in range(1, len(ra_pkt.layers())):
        layer = ra_pkt.getlayer(i)
        layer_bytes = get_hdr_bytes(ra_pkt.getlayer(i))
        if type(layer) == ICMPv6NDOptPrefixInfo:
            prefix_layer = ICMPv6NDOptPrefixInfo(layer_bytes)
            if ipaddress.ip_address(layer.prefix).is_global:
                global_prefix = ICMPv6NDOptPrefixInfo(layer_bytes)
#                global_prefix.validlifetime = 600
#                global_prefix.preferredlifetime = 600
                new_pkt /= global_prefix
            else:
                logging.info("found non-global")
                return
        elif type(layer) == ICMPv6NDOptDNSSL:
            logging.info('found dnssl signature layer, returning')
            return 
        elif type(layer) == ICMPv6NDOptSrcLLAddr:
            new_pkt /= ICMPv6NDOptSrcLLAddr(layer_bytes)
#        elif type(layer) == ICMPv6NDOptRDNSS:
#            new_pkt /= ICMPv6NDOptRDNSS(layer_bytes)
        else:
            logging.info(f'ignoring layer: {ra_pkt.getlayer(i).__class__}')

    # create a new prefix layer for site local
#    site_local_prefix = ICMPv6NDOptPrefixInfo(validlifetime=600, preferredlifetime=600, prefix='fd82::', L=1, A=0)
#    new_pkt /= site_local_prefix

    # raincity dns
    raincity_dns = None
    for addr in netifaces.ifaddresses('lan_bridge')[netifaces.AF_INET6]:
        if '%' in addr['addr']:
            aaaa = addr['addr'].split('%', 1)[0]
        else:
            aaaa = addr['addr']
        if ipaddress.ip_address(aaaa).is_link_local:
            raincity_dns = ICMPv6NDOptRDNSS(lifetime=600, dns=[aaaa])
#    raincity_dns = ICMPv6NDOptRDNSS(lifetime=3600, dns=['fd82::1'])
    if raincity_dns is not None:
        new_pkt /= raincity_dns
        raincity_dnssl = ICMPv6NDOptDNSSL(lifetime=600, searchlist=['lan'])
        new_pkt /= raincity_dnssl

    sendp(new_pkt, iface='tmnet6') #tmnet6')

def main():
    logging.basicConfig(level=logging.INFO)
    sniff(iface='tmnet6', filter='icmp6 and ip6[40] = 134', prn=callback)

if __name__ == '__main__':
    main()

