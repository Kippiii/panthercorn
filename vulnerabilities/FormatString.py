"""
Deals with finding format string attack vulnerabilites
"""

from typing import List


# Ash

class FormatString:
    pass  # TODO


def get_format_string_vulns() -> List[FormatString]:
    if 'fopen' in test:
        print("fopen")

    elif 'pwnme' in test:
        print("Write_prim")
     
    elif 'putchar' in test:
        print("got_overwrite")
    
    else:
        print("libc leak")    
