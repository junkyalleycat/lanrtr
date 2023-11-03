#!/usr/bin/env python3

import time
from scapy.all import sniff, sendp
from collections import namedtuple
import asyncio
import logging
import argparse
import signal
import threading
import functools
import os
from lru import LRU

from .common import *

async def send_pkt(if_name, pkt):
    send_f = functools.partial(sendp, pkt, iface=if_name, verbose=False)
    await asyncio.get_event_loop().run_in_executor(None, send_f)

async def send_nbradv(if_name, src, dst, tgt):
    nbradv = Ether(src=src[0], dst=dst[0])
    nbradv /= IPv6(src=src[1], dst=dst[1])
    nbradv /= ICMPv6ND_NA(R=1, S=1, O=1, tgt=tgt)
    nbradv /= ICMPv6NDOptDstLLAddr(lladdr=src[0])
    nbradv = nbradv.build()
    logging.debug(f'advertising: {tgt}')
    await send_pkt(if_name, nbradv)

async def send_nbrsol(if_name, src, dst, tgt):
    nbrsol = Ether(src=src[0], dst=dst[0])
    nbrsol /= IPv6(src=src[1], dst=dst[1])
    nbrsol /= ICMPv6ND_NS(tgt=tgt)
    nbrsol /= ICMPv6NDOptSrcLLAddr(lladdr=src[0])
    nbrsol = nbrsol.build()
    logging.debug(f'soliciting: {tgt}')
    await send_pkt(if_name, nbrsol)

# TODO consider consulting ndp table instead?
# TODO consider caching nbradv?
async def worker(config, pkt_q):
    nbrsols = LRU(100)
    while True:
        pkt = await pkt_q.get()
        pkt_type = type(pkt.getlayer(2))
        if pkt_type is ICMPv6ND_NS:
            if pkt.sniffed_on != config.wan_if:
                continue
            wan_nbrsol = pkt
            wan_nbrsol_src_addr = ipaddress.ip_address(wan_nbrsol.getlayer(1).src)
            tgt = ipaddress.ip_address(wan_nbrsol.getlayer(2).tgt)
            if (config.north_rt_addr is not None) and (config.north_rt_addr != wan_nbrsol_src_addr):
                logging.debug(f'ignoring solicitation (unknown source): {tgt}')
                continue
            wan_if_addrs = get_if_addrs(config.wan_if)
            lan_if_addrs = get_if_addrs(config.lan_if)
            if (tgt == wan_if_addrs.linklocal) \
                    or (tgt in wan_if_addrs.gaddrs) \
                    or (tgt in lan_if_addrs.gaddrs):
                src = (wan_if_addrs.lladdr, wan_if_addrs.linklocal)
                dst = (wan_nbrsol.src, wan_nbrsol.getlayer(1).src)
                await send_nbradv(config.wan_if, src, dst, tgt)
            elif tgt.is_global:
                src = (lan_if_addrs.lladdr, lan_if_addrs.linklocal)
                dst = (wan_nbrsol.dst, wan_nbrsol.getlayer(1).dst)
                nbrsols[tgt] = wan_nbrsol
                await send_nbrsol(config.lan_if, src, dst, tgt)
            else:
                logging.debug(f'ignoring solicitation: {tgt}')
        elif pkt_type is ICMPv6ND_NA:
            if pkt.sniffed_on != config.lan_if:
                continue
            lan_nbradv = pkt
            tgt = ipaddress.ip_address(lan_nbradv.getlayer(2).tgt)
            wan_nbrsol = nbrsols.pop(tgt, None)
            if wan_nbrsol is not None:
                wan_if_addrs = get_if_addrs(config.wan_if)
                src = (wan_if_addrs.lladdr, wan_if_addrs.linklocal)
                dst = (wan_nbrsol.src, wan_nbrsol.getlayer(1).src)
                await send_nbradv(config.wan_if, src, dst, tgt)
        else:
            logging.error(f'unexpected packet: {type(pkt.getlayer(2))}')

Config = namedtuple('Config', ['wan_if', 'lan_if', 'north_rt_addr'])

async def main():
    logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)-8s %(message)s')

    loop = asyncio.get_event_loop()
    finish = asyncio.Event()

    loop.add_signal_handler(signal.SIGINT, finish.set)
    loop.add_signal_handler(signal.SIGTERM, finish.set)

    def uncaught_exception(loop, context):
        loop.default_exception_handler(context)
        finish.set()

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--wan-if', required=True)
    parser.add_argument('--lan-if', required=True)
    parser.add_argument('--north-rt-addr')
    args = parser.parse_args()

    if args.debug:
        logging.root.setLevel(logging.DEBUG)

    if args.north_rt_addr is None:
        north_rt_addr = None
    else:
        north_rt_addr = ipaddress.ip_address(args.north_rt_addr)

    config = Config(args.wan_if, args.lan_if, north_rt_addr)
   
    pkt_q = asyncio.Queue()

    finish_t = asyncio.create_task(finish.wait())
    sniffer_if_names = [config.wan_if, config.lan_if]
    sniffer_pfilter = 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)'
    sniffer_t = asyncio.create_task(sniffer(sniffer_if_names, sniffer_pfilter, pkt_q.put_nowait))
    worker_t = asyncio.create_task(worker(config, pkt_q))

    await asyncio.wait([finish_t, sniffer_t, worker_t], return_when=asyncio.FIRST_COMPLETED)
    finish.set()

def entry():
    asyncio.run(main())

