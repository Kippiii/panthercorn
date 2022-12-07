"""
Deals with finding format string attack vulnerabilites
"""

from typing import List
import re
from pwn import *


POINTER_RE = r"""0x([0-9A-F]+)"""


class FormatString:
    payload_start: bytes

    def __init__(self, payload_start: bytes) -> None:
        self.payload_start = payload_start


def get_format_string_vulns(bin_path: str) -> List[FormatString]:
    vulns = []
    p = process(bin_path)
    num_payloads = 0
    while p.poll() is None:
        if p.can_recieve(timeout=1):
            out = p.recvS()
            comp = re.compile(POINTER_RE)
            srch = re.search(out)
            if srch:
                vulns.append(FormatString(b"%p.%p.%p\n" * (num_payloads - 1)))
        else:
            num_payloads += 1
            p.send(b"%p.%p.%p\n")

    return vulns
