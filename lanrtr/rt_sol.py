#!/usr/bin/env python3

from collections import namedtuple
import tempfile
import os
from scapy.all import sendp
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
    rtsol_if_addrs = get_if_addrs(rtsol_if)
    rtsol = Ether(src=rtsol_if_addrs.lladdr, dst=ipv6mcast_02.mac)
    rtsol /= IPv6(src=rtsol_if_addrs.linklocal, dst=ipv6mcast_02.addr)
    rtsol /= ICMPv6ND_RS()
    rtsol /= ICMPv6NDOptSrcLLAddr(lladdr=rtsol_if_addrs.lladdr)
    rtsol = rtsol.build()
    logging.debug(f'soliciting router: {ipv6mcast_02.addr}')
    await asyncio.get_event_loop().run_in_executor(None, functools.partial(sendp, rtsol, iface=rtsol_if, verbose=False))

# SIGUSR1 should trigger a redo of the outer loop
async def worker(config, pkt_q, resol_s, rtadv_action_handler):
    while True:
        if not resol_s.locked():
            await send_rtsol(config)
        try:
            rtadv = await asyncio.wait_for(pkt_q.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        rtadv_src_addr = ipaddress.ip_address(rtadv.getlayer(1).src)
        logging.debug(f'received router advertisement: {rtadv_src_addr}')
        if (config.north_rt_addr is not None) and (config.north_rt_addr != rtadv_src_addr):
            logging.debug(f'ignoring rtadv from {rtadv_src_addr}')
            continue
        await rtadv_action_handler.rtadv(rtadv_src_addr, rtadv)
        if not resol_s.locked():
            await resol_s.acquire()

# invoke the user script, simply log errors
class ScriptActionHandler:
    
    def __init__(self, config, rtadv_script):
        self.config = config
        self.rtadv_script = rtadv_script

    async def invoke(self, action, *extra_args):
        args = [self.rtadv_script, action, '-i', self.config.rtsol_if, *extra_args]
        try:
            child_t = await asyncio.create_subprocess_exec(*args)
            if (await child_t.wait()) != 0:
                logging.error("unknown script error")
        except BaseException as e:
            logging.error(e)

    async def start(self):
        await self.invoke('start')

    async def rtadv(self, rtadv_src_addr, rtadv):
        with tempfile.NamedTemporaryFile() as rtadv_file:
            rtadv_file.write(json.dumps(rtadv.getlayer(2), cls=ICMPv6JSONEncoder).encode())
            rtadv_file.flush()
            await self.invoke('rtadv', '--rtadv-src-addr', str(rtadv_src_addr), '--rtadv-file', rtadv_file.name)

    async def stop(self):
        await self.invoke('stop')

# default debug handler
class DumpActionHandler:

    async def start(self):
        print("action:start")

    async def rtadv(self, rtadv_src_addr, rtadv):
        print("action:rtadv")
        print(json.dumps({'rtadv_src_addr': str(rtadv_src_addr), 'rtadv': rtadv.getlayer(2)}, cls=ICMPv6JSONEncoder))

    async def stop(self):
        print("action:stop")

Config = namedtuple('Config', ['rtsol_if', 'north_rt_addr'])

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
    parser.add_argument('--north-rt-addr', type=ipaddress.ip_address)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.root.setLevel(logging.DEBUG)

    config = Config(args.i, args.north_rt_addr)

    if args.s is None:
        rtadv_action_handler = DumpActionHandler()
    else:
        rtadv_action_handler = ScriptActionHandler(config, args.s)

    pkt_q = asyncio.Queue()

    resol_s = asyncio.BoundedSemaphore(1) 
    def sigusr1():
        try:
            resol_s.release()
        except ValueError:
            pass
    loop.add_signal_handler(signal.SIGUSR1, sigusr1)

    await rtadv_action_handler.start()

    finish_t = asyncio.create_task(finish.wait())
    sniffer_if_names = [config.rtsol_if]
    sniffer_pfilter = 'icmp6 and ip6[40] == 134'
    sniffer_t = asyncio.create_task(sniffer(sniffer_if_names, sniffer_pfilter, pkt_q.put_nowait))
    worker_t = asyncio.create_task(worker(config, pkt_q, resol_s, rtadv_action_handler))

    await asyncio.wait([finish_t, sniffer_t, worker_t], return_when=asyncio.FIRST_COMPLETED)
    finish.set()

    await rtadv_action_handler.stop()

def entry():
    asyncio.run(main())

