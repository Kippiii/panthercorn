"""
Deals with finding stack overflow vulnerabilites
"""

from typing import List
from pwn import *
import os

# re isn't used. Remove later if that doesn't change.
import re


class StackOverflow:
    payload_start: bytes
    bin_path: str

    def __init__(self, payload_start: bytes, bin_path: str):
        self.bin_path = bin_path
        self.payload_start = payload_start


def get_overflow_size(p, register='rsp', size_of_input=5000) -> int:
    """
    Returns -1 if nothing is found in the core file for the given register.
    Modify size_of_input to try larger/smaller buffer.
    Register defaults to rsp but function can be used for any.
    """
    p.sendline(cyclic(size_of_input, n=8))
    p.wait()
    core = p.corefile
    offset = cyclic_find(core.read(core.registers[register], 8), n=8)
    os.remove(core.file.name)
    return offset


def get_stack_overflow_vulns(bin_path) -> List[StackOverflow]:
    vulns = []
    p = process(bin_path)

    while p.poll() is None:
        if p.can_recv(timeout=1):
            try:
                p.recv()
            except EOFError:
                continue
        else:
            padding = get_overflow_size(p)
            if padding == -1:
                continue

            vulns.append(StackOverflow(b"A" * padding, bin_path))

    return vulns


