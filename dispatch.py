"""
Determines which exploits to call
"""

import re
from pwn import ELF, process

pointer_re = r"""0x[0-9a-f]*"""

def dispatch_exploits(file_path: str) -> None:
    """
    Calls exploits based on possible ones
    """
    syms = ELF(file_path).symbols.keys()

    # Get all vulnerabilites
    vulns = ?

    if has_stack_overflow(vulns):
        # ret2win
        if 'win' in syms:
            pass

        # ret2system
        if 'system' in syms:
            pass

        # ret2execve
        if 'execve' in syms:
            pass

        # ret2syscall
        if 'syscall' in syms:
            pass

        # ret2libc
        output = process(file_path).recv()
        comp = re.compile(pointer_re)
        if comp.match(output) is not None:
            pass

        # ropwrite
        if 'pwnme' in syms:
            pass

    # Nick (Format)