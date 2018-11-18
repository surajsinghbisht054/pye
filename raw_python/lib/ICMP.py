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

import socket
# import modules
import struct

from .util import Packet
from .Ether import EtherPacket
from .IP import LoadIP

# Header is type (8), code (8), checksum (16), id (16), sequence (16)
#    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
ICMP_STRUCTURE_FMT = 'bbHHh'
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.

ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
}


class ICMPPacket(Packet):
    def __init__(self, _type=ICMP_ECHO_REQUEST, code=0, checksum=0, _id=1, _seq=1, data=b''):
        self.type = _type
        self.code = code
        self.checksum = checksum
        self.id = _id
        self.seq = _seq
        self.data = data
        self.raw = None
        self.create_icmp_field()

    def create_icmp_field(self):
        _raw = struct.pack(ICMP_STRUCTURE_FMT, self.type, self.code, self.checksum, self.id, self.seq)
        # calculate checksum
        self.checksum = self.calc_checksum(_raw + self.data)
        self.raw = struct.pack(ICMP_STRUCTURE_FMT, self.type, self.code, self.checksum, self.id, self.seq)


# ICMP HEADER Extraction
def parse_icmp_header(data):
    icmph = struct.unpack(ICMP_STRUCTURE_FMT, data)
    data = {
        'type': icmph[0],
        "code": icmph[1],
        "checksum": icmph[2],
        'id': icmph[3],
        'seq': icmph[4],
    }
    return data


def main():
    icmp = ICMPPacket()
    print(parse_icmp_header(icmp.raw))
    ip = LoadIP(tcp=icmp, ip_proto=socket.IPPROTO_ICMP)
    eth = EtherPacket(data=ip)

    try:
        from ..samples.wsk import ShowPacket
        pkt = eth.raw + ip.raw + icmp.raw
        ShowPacket([pkt], link_type=1)
    except Exception as e:
        print(e)
        print("[+] Unable To Find pye.samples.wsk script.")
    return


if __name__ == '__main__':
    main()
