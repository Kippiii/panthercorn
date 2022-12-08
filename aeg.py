from pwn import args
import logging

from dispatch import dispatch_exploits

logging.getLogger('pwnlib').setLevel(logging.ERROR)

dispatch_exploits(args.BIN)
