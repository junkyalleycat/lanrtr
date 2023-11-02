# ra-support
ipv6 hacky shack

Created this to mimic a fake ownership of an ipv6 subnet.  Because my provider (tmobile) does not provide prefix delegations, and because I wanted to control ipv6 on my lan, I needed a solution to do the following things:

1) fetch router advertisements from my ISP modem in order to discover the default route and the global prefix
2) advertise neighbors on behalf of my lan router to "fake" ownership

The following nouns and their descriptions are the primary objects used by the software:
wan -- wan interface, this is what shares the same link line as the router
lan -- lan interface, this is the internal interface that all computers on the lan are routed through
north-rt -- the router "north" of the wan, probably the ISP modem

The wan and the lan are assumed to coexist on the same host, the the wan sharing a link connection with the north-rt.

These problems are solved by two provided scripts:

## rt-sol
rt-sol solicits an interface for router advertisements.  It then calls a script when an advertisement arrives, allowing the script to do whatever with the advertisement.  In the example script (under etc), it simply adds the router as the default gateway, and adds a global static address to the lan interface.

Example usage:

`rt-sol -i wan_if -s /usr/local/etc/rt-sol/rt-sol-script --north-rt-addr fe80::1982 --debug`
- -i : wan interface
- -s : script to execute upon receiving rtadv
- --north-rt-addr : link-local address of the north router, specified in order to help filter incoming advertisements (not required, but seems like a good idea)
- --debug : set debug level logging
  
## nbr-adv
nbr-adv is responsible for listening on the wan interface for neighbor solicitations, forwarding them to the lan where appropriate, and then answering back to the north-rt when the solicitations are answered on the lan.

Currently, there are a few different types of addresses that nbr-adv will advertise:
1) neighbors in lan that have a global address
2) the link-local of the wan interface
3) the global of the wan interface
4) the link-local of the lan interface
5) the global of the lan interface

Example usage:

`nbr-adv --wan-if wan_if --lan-if lan_if --north-rt-addr fe80::1982 --debug`
- --wan-if : wan interface
- --lan-if : lan interface
- --north-rt-addr : link-local address of the north router, specified in order to help filter incoming advertisements (not required, but seems like a good idea)
- --debug : set debug level logging

Because the nbr-adv program has no knowledge of the north-rt global subnet, it assumes that any global address that responds to a solicitation (or is aliased to either wan/lan) is valid to advertise back to the north-rt when a solicitation for a global address comes in.

## Basic setup
The basic setup to make this stuff work is as follows:

1) Install ra-support directory in /opt/ra-support.  This is just the assumed directory where everything lives, sorry
2) Run /opt/ra-support/bin/bootstrap.  This script creates a venv under /opt/ra-support/venv and installs the dependencies, it's not a friendly setup but it works for me.
3) Create a filter rule to prevent wan neighbor solicitations from coming through.  The nbr-sol program will answer solicitations for the wan (link-local), so no need to selectively filter, just filter all neighbor solicitations from wan.
4) Configure the wan interface to *not* have ACCEPT_RTADV.  Because the router solicitations are handled by rt-sol, we don't want the kernel to mess with them.
5) Run rt-sol and nbr-adv.  See the rc.d directory for startup scripts, they expect all of this to be installed in /opt/ra-support
6) Run rtadvd on your lan interface with whatever configuration you want to start advertising ipv6 to your lan

At this point, assuming you have a script to parse the rt-sol and setup the default route / lan, then you should have a working ipv6 lan network where you control the subnet.  You might need to tweak the configuration and the code to bend it to work with your setup, as will be obvious if
you read through any of it the code was basically written to serve a specific setup, and does not have a lot of flexability or configuration options.

## Requirements
1) python >= 3.8
2) BPF
