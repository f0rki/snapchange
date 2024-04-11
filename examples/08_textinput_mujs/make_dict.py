#!/usr/bin/env python

import string
import sys

entries = set()

for line in open(sys.argv[1], "r").readlines():
    line = line.strip()
    if line:
        entries.add(line)


for line in entries:
    fname = hex(hash(line))[2:] + "_"
    if all(c in string.ascii_letters for c in line):
        fname += line
    with open("./dict/" + fname.strip(), "w") as f:
        f.write(line)
