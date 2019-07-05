#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#           Copyright 2018 Dept. CSE SUSTech
#           Copyright 2018 Suraj Singh Bisht
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# --------------------------------------------------------------------------
#                         Don't Remove Authors Info                        |
# --------------------------------------------------------------------------


__author__ = 'Suraj Singh Bisht, HHQ. ZHANG'
__credit__ = '["Suraj Singh Bisht",]'
__contact__ = 'contact@jinlab.cn'
__copyright__ = 'Copyright 2018 Dept. CSE SUSTech'
__license__ = 'Apache 2.0'
__Update__ = '2018-01-11 12:33:09.399381'
__version__ = '0.1'
__maintainer__ = 'HHQ. ZHANG'
__status__ = 'Production'

import array
import fcntl
import socket
import struct
from binascii import hexlify


# # found on <http://code.activestate.com/recipes/439093/#c1>
# get all interface names
def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.

    bytes = max_possible * 32

    # Create a dummy socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    names = array.array('B', b'\0' * bytes)

    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]

    namestr = names.tostring()

    lst = []

    for i in range(0, outbytes, 40):
        name = namestr[i:i + 16].split(b'\0', 1)[0]
        ip = namestr[i + 20:i + 24]
        lst.append((name, socket.inet_ntoa(ip)))

    s.close()
    return lst


def get_mac(interface, p=0):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface.decode(), p))
    mac = hexlify(s.getsockname()[4])
    s.close()
    return mac


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def get_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    s.connect(('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 1))

    ip = s.getsockname()[0]

    s.close()
    return ip


if __name__ == '__main__':
    print(all_interfaces())
    print(get_ip())
    print(get_ipv6())
