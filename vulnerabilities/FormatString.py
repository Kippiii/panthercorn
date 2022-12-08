"""
Deals with finding format string attack vulnerabilities
"""

from typing import List
import re
from pwn import *
from config import *

# remove if unneeded
# POINTER_RE = r"""0x([0-9A-F]+)"""


class FormatString:
    payload_start: bytes
    bin_path: str

    def __init__(self, payload_start: bytes, bin_path: str) -> None:
        self.payload_start = payload_start
        self.bin_path = bin_path


def get_format_string_vulns(bin_path: str) -> List[FormatString]:
    vulns = []
    p = process([bin_path])
    num_payloads = 0
    max_checks = 5
    while p.poll() is None and num_payloads <= max_checks:
        if p.can_recv(timeout=1):
            try:
                out = p.recvS()
            except EOFError:
                continue
            # comp = re.compile(POINTER_RE)
            comp = re.compile(pointer_re)
            srch = comp.search(out)
            if srch:
                vulns.append(FormatString(b"%p.%p.%p\n" * (num_payloads - 1), bin_path))
        else:
            num_payloads += 1
            p.send(b"%p.%p.%p\n")
    p.kill()

    return vulns