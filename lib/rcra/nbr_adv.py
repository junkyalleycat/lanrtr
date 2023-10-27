#!/usr/bin/env python3

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

from .common import *

default_rt_addr = ipaddress.ip_address('fe80::aedf:9fff:fe88:594e')

def sniffer(config, loop, pkt_q):
    try:
        def handler(pkt):
            loop.call_soon_threadsafe(pkt_q.put_nowait, pkt)
        sniff(store=0, iface=config.nbradv_if, filter='icmp6 and ip6[40] == 135', prn=handler)
    except Exception as e:
        logging.exception(e)

async def worker(config, pkt_q):
    while True:
        nbrsol = await pkt_q.get()
        nbrsol_src_addr = ipaddress.ip_address(nbrsol.getlayer(1).src)
        if config.rt_addr != nbrsol_src_addr:
            logging.debug(f'ignoring nbrsol from {nbrsol_src_addr}')
            continue
        tgt = ipaddress.ip_address(nbrsol.getlayer(2).tgt)
        if tgt.is_global:
            nbradv_if_info = get_if_info(config.nbradv_if)
            nbradv = Ether(src=nbradv_if_info.mac, dst=nbrsol.src)
            nbradv /= IPv6(src=nbradv_if_info.addr, dst=nbrsol.getlayer(1).src)
            nbradv /= ICMPv6ND_NA(R=1, S=1, O=1, tgt=tgt)
            nbradv /= ICMPv6NDOptDstLLAddr(lladdr=nbradv_if_info.mac)
            logging.debug(f'sending nbradv: {nbradv}')
            nbradv = nbradv.build()
            asyncio.get_event_loop().run_in_executor(None, functools.partial(sendp, nbradv, iface=config.nbradv_if, verbose=False))

Config = namedtuple('Config', ['nbradv_if', 'rt_addr'])

async def main():
    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    finish = asyncio.Event()

    loop.add_signal_handler(signal.SIGINT, finish.set)
    loop.add_signal_handler(signal.SIGTERM, finish.set)

    def uncaught_exception(loop, context):
        loop.default_exception_handler(context)
        finish.set()

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', metavar='nbradv_if', required=True)
    parser.add_argument('--rt-addr')
    args = parser.parse_args()

    if args.rt_addr is None:
        rt_addr = default_rt_addr
    else:
        rt_addr = ipaddress.ip_address(args.rt_addr)

    config = Config(args.i, rt_addr)
   
    pkt_q = asyncio.Queue()

    sniffer_th = threading.Thread(target=sniffer, args=(config, loop, pkt_q), daemon=True)
    sniffer_th.start()

    worker_t = asyncio.create_task(worker(config, pkt_q))
    finish_t = asyncio.create_task(finish.wait())

    logging.debug(f'pid: {os.getpid()}')

    await asyncio.wait([finish_t, worker_t], return_when=asyncio.FIRST_COMPLETED)
    finish.set()

if __name__ == '__main__':
    asyncio.run(main())

