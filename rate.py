#!/usr/bin/env python

import sys, socket, struct, hashlib, hmac

key = 'hash-key'

m = struct.pack('!bbIII64s512s', 1, 4, 0, 0, 3600, '', sys.argv[1]);
m += hmac.new(key.decode('hex'), m, hashlib.sha1).digest()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(m, ('192.168.0.12', 13131))
