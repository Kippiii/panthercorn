pointer_re = r"""0x[0-9a-fA-F]*"""
libc_path = '/usr/lib/x86_64-linux-gnu/libc-2.32.so'
vuln_printfs = ['printf', 'fprintf', 'sprintf', 'vprintf', 'snprintf', 'vsnprintf', 'vfprintf']
flag_re = r"""(flag\{[A-Za-z_\-0-9]^{32}\})"""
