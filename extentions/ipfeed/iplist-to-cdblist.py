#!/usr/bin/env python

import re
from sys import exit, argv

try:
    if len(argv) != 3:
        print("Bad arguments. Try: iplist-to-cdblist.py input output")
        exit(1)

    ip_regex = re.compile("^((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:/(\d{1,2}){0,1}|)")
    first_time = True
    cdir_conversion = {"32": 4, "24": 3, "16": 2, "8": 1}

    fo = open(argv[2], 'w')

    with open(argv[1]) as f:
        for line in f:
            match = ip_regex.match(line.rstrip('\r\n'))

            if not match:  # Read just lines that start with an IP
                continue

            ip = match.group(1)
            mask = match.group(2)

            if mask:  # Convert allowed masks (32, 24, 16, 8)
                ip = ip.split('.')
                if mask in cdir_conversion:
                    ip = '.'.join(ip[:cdir_conversion[mask]])
                    if mask != "32":
                        ip += "."

                else:
                    continue

            ip += ":"  # CDB List format

            if first_time:
                fo.write(ip)
                first_time = False
            else:
                fo.write("\n" + ip)

    fo.close()

    print("[{0}] -> [{1}]".format(argv[1], argv[2]))

except Exception as e:
    print("Error:\n{0}\nExiting...".format(e))
    exit(1)
