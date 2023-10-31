#!/usr/bin/env python3

from collections import namedtuple
import tempfile
import os
from scapy.all import sniff
from scapy.all import sendp
import uvloop
import asyncio
import logging
import signal
import argparse
import json
import threading
import functools

from .common import *

async def send_rtsol(config):
    rtsol_if = config.rtsol_if
    rtsol_if_info = get_if_info(rtsol_if)
    rtsol = Ether(src=rtsol_if_info.mac, dst=ipv6mcast_02.mac)
    rtsol /= IPv6(src=rtsol_if_info.addr, dst=ipv6mcast_02.addr)
    rtsol /= ICMPv6ND_RS()
    rtsol /= ICMPv6NDOptSrcLLAddr(lladdr=rtsol_if_info.mac)
    rtsol = rtsol.build()
    await asyncio.get_event_loop().run_in_executor(None, functools.partial(sendp, rtsol, iface=rtsol_if, verbose=False))

# SIGUSR1 should trigger a redo of the outer loop
async def worker(config, pkt_q, resol_s):
    previous_rtadv = None
    while True:
        if not resol_s.locked():
            await send_rtsol(config)
        try:
            rtadv = await asyncio.wait_for(pkt_q.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        rtadv_src_addr = ipaddress.ip_address(rtadv.getlayer(1).src)
        if (config.north_rt_addr is not None) and (config.north_rt_addr != rtadv_src_addr):
            logging.debug(f'ignoring rtadv from {rtadv_src_addr}')
            continue
        if (not resol_s.locked()) or (rtadv != previous_rtadv):
            await config.rtadv_action(rtadv_src_addr, rtadv)
            previous_rtadv = rtadv
        if not resol_s.locked():
            await resol_s.acquire()

async def invoke_rtadv_script(rtadv_script, rtsol_if, rtadv_src_addr, rtadv):
    with tempfile.NamedTemporaryFile() as rtadv_file:
        rtadv_file.write(json.dumps(rtadv.getlayer(2), cls=ICMPv6JSONEncoder).encode())
        rtadv_file.flush()
        try:
            args = [rtadv_script, 'rtadv', '-i', rtsol_if, '--rtadv-src-addr', str(rtadv_src_addr), '--rtadv-file', rtadv_file.name]
            child_t = await asyncio.create_subprocess_exec(*args)
            await child_t.wait()
        except Exception as e:
            logging.error(e)

async def dump_rtadv(rtadv_src_addr, rtadv):
    print(json.dumps({'rtadv_src_addr': str(rtadv_src_addr), 'rtadv': rtadv.getlayer(2)}, cls=ICMPv6JSONEncoder))

Config = namedtuple('Config', ['rtsol_if', 'rtadv_action', 'north_rt_addr'])

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
    parser.add_argument('-i', metavar='rtsol_if', required=True)
    parser.add_argument('-s', metavar='rtadv_script')
    parser.add_argument('--north-rt-addr', required=True)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.root.setLevel(logging.DEBUG)

    if args.s is None:
        rtadv_action = dump_rtadv
    else:
        rtadv_action = functools.partial(invoke_rtadv_script, args.s, args.i)

    if args.north_rt_addr is None:
        north_rt_addr = None
    else:
        north_rt_addr = ipaddress.ip_address(args.north_rt_addr)

    config = Config(args.i, rtadv_action, north_rt_addr)

    pkt_q = asyncio.Queue()

    resol_s = asyncio.BoundedSemaphore(1) 
    def sigusr1():
        try:
            resol_s.release()
        except ValueError:
            pass
    loop.add_signal_handler(signal.SIGUSR1, sigusr1)

    finish_t = asyncio.create_task(finish.wait())
    sniffer_if_names = [config.rtsol_if]
    sniffer_pfilter = 'icmp6 and ip6[40] == 134'
    sniffer_t = asyncio.create_task(sniffer(sniffer_if_names, sniffer_pfilter, pkt_q.put_nowait))
    worker_t = asyncio.create_task(worker(config, pkt_q, resol_s))

    await asyncio.wait([finish_t, sniffer_t, worker_t], return_when=asyncio.FIRST_COMPLETED)
    finish.set()

if __name__ == '__main__':
    asyncio.run(main())

