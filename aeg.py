from pwn import args
import logging

from dispatch import dispatch_exploits

logging.getLogger('pwnlib').setLevel(logging.WARNING)

# dispatch_exploits(args.BIN)
dispatch_exploits('/home/falco/Desktop/SWRE/bins/bin-ret2system-0')
