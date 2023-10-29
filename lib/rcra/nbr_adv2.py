#!/usr/bin/env python3

import time
from scapy.all import sniff, sendp
from collections import namedtuple
import asyncio
import logging
import argparse
import uvloop
import signal
import threading
import functools
import os
from lru import LRU

from .common import *

default_rt_addr = ipaddress.ip_address('fe80::aedf:9fff:fe88:594e')

def sniffer(config, loop, pkt_q):
    try:
        def handler(pkt):
            loop.call_soon_threadsafe(pkt_q.put_nowait, pkt)
        sniff(store=0, iface=[config.wan_if, config.lan_if], filter='icmp6 and (ip6[40] == 135 or ip6[40] == 136)', prn=handler)
    except Exception as e:
        logging.exception(e)

def send_pkt(if_name, pkt):
    asyncio.get_event_loop().run_in_executor(None, functools.partial(sendp, pkt, iface=if_name, verbose=False))

# TODO consider consulting ndp table insteead?
async def worker(config, pkt_q):
#    nbrsols = {}
    nbrsols = LRU(10)
    while True:
        pkt = await pkt_q.get()
#        print(pkt.time)
        if type(pkt.getlayer(2)) is ICMPv6ND_NS:
            if pkt.sniffed_on != config.wan_if:
                continue
            wan_nbrsol = pkt
            wan_nbrsol_src_addr = ipaddress.ip_address(wan_nbrsol.getlayer(1).src)
            if config.rt_addr != wan_nbrsol_src_addr:
                logging.debug(f'ignoring nbrsol from {wan_nbrsol_src_addr}')
                continue
            tgt = ipaddress.ip_address(wan_nbrsol.getlayer(2).tgt)
            if tgt.is_global:
                nbrsols[tgt] = wan_nbrsol
                lan_if_info = get_if_info(config.lan_if)
                lan_nbrsol = Ether(src=lan_if_info.mac, dst=wan_nbrsol.dst)
                lan_nbrsol /= IPv6(src=lan_if_info.addr, dst=wan_nbrsol.getlayer(1).dst)
                lan_nbrsol /= ICMPv6ND_NS(tgt=tgt)
                lan_nbrsol /= ICMPv6NDOptSrcLLAddr(lladdr=lan_if_info.mac)
                lan_nbrsol = lan_nbrsol.build()
                send_pkt(config.lan_if, lan_nbrsol)
        elif type(pkt.getlayer(2)) is ICMPv6ND_NA:
            print(len(nbrsols))
            if pkt.sniffed_on != config.lan_if:
                continue
            lan_nbradv = pkt
            tgt = ipaddress.ip_address(lan_nbradv.getlayer(2).tgt)
            nbrsol = nbrsols.pop(tgt, None)
            if nbrsol is not None:
                wan_if_info = get_if_info(config.wan_if)
                wan_nbradv = Ether(src=wan_if_info.mac, dst=nbrsol.src)
                wan_nbradv /= IPv6(src=wan_if_info.addr, dst=nbrsol.getlayer(1).src)
                wan_nbradv /= ICMPv6ND_NA(R=1, S=1, O=1, tgt=tgt)
                wan_nbradv /= ICMPv6NDOptDstLLAddr(lladdr=wan_if_info.mac)
                wan_nbradv = wan_nbradv.build()
                send_pkt(config.wan_if, wan_nbradv)
        else:
            logging.error(f'unexpected packet: {type(pkt.getlayer(2))}')

Config = namedtuple('Config', ['wan_if', 'lan_if', 'rt_addr'])

async def main():
    logging.basicConfig(level=logging.INFO)

    loop = asyncio.get_event_loop()
    finish = asyncio.Event()

    loop.add_signal_handler(signal.SIGINT, finish.set)
    loop.add_signal_handler(signal.SIGTERM, finish.set)

    def uncaught_exception(loop, context):
        loop.default_exception_handler(context)
        finish.set()

    parser = argparse.ArgumentParser()
    parser.add_argument('--wan-if', required=True)
    parser.add_argument('--lan-if', required=True)
    parser.add_argument('--rt-addr')
    args = parser.parse_args()

    if args.rt_addr is None:
        rt_addr = default_rt_addr
    else:
        rt_addr = ipaddress.ip_address(args.rt_addr)

    config = Config(args.wan_if, args.lan_if, rt_addr)
   
    pkt_q = asyncio.Queue()

    sniffer_th = threading.Thread(target=sniffer, args=(config, loop, pkt_q), daemon=True)
    sniffer_th.start()

    worker_t = asyncio.create_task(worker(config, pkt_q))
    finish_t = asyncio.create_task(finish.wait())

    await asyncio.wait([finish_t, worker_t], return_when=asyncio.FIRST_COMPLETED)
    finish.set()

if __name__ == '__main__':
    asyncio.run(main())

