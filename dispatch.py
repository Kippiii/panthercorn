"""
Determines which exploits to call
"""

import re
from pwn import ELF, process
from typing import List, Union

from vulnerabilities import FormatString, StackOverflow, get_format_string_vulns, get_stack_overflow_vulns
from exploits import ret2win, ret2system, ret2execve, ret2syscall, ret2libc, ropwrite, stack_leak, write_prim, got_overwrite, libc_leak, ret2win_args

pointer_re = r"""0x[0-9a-f]*"""


def end_prog(flag: str) -> None:
    print(f"Flag is {flag}")
    exit(0)


def dispatch_exploits(file_path: str) -> None:
    """
    Calls exploits based on possible ones
    """
    syms = ELF(file_path).symbols.keys()

    # Get all vulnerabilites
    vulns: List[Union[FormatString, StackOverflow]] = get_format_string_vulns(file_path) + get_stack_overflow_vulns(file_path)

    for vuln in vulns:
        if isinstance(vuln, StackOverflow):
            # ret2win
            if 'win' in syms:
                flag = ret2win(vuln)
                if flag is not None:
                    end_prog(flag)
                flag = ret2win_args(vuln)
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
            output = process([file_path]).recvS()
            comp = re.compile(pointer_re)
            if comp.search(output) is not None:
                flag = ret2libc(vuln)
                if flag is not None:
                    end_prog(flag)

            # ropwrite
            if 'pwnme' in syms:
                flag = ropwrite(vuln)
                if flag is not None:
                    end_prog(flag)

        elif isinstance(vuln, FormatString):
            vuln_printfs = ['printf', 'fprintf', 'sprintf', 'vprintf', 'snprintf', 'vsnprintf', 'vfprintf']
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

            else:
                pass  # TODO
                
        else:
            pass  # TODO
    for vuln1 in vulns:
        for vuln2 in vulns:
            if isinstance(vuln1, FormatString) and isinstance(vuln2, StackOverflow):
                flag = libc_leak(vuln1, vuln2)
                if flag is not None:
                    end_prog(flag)
        