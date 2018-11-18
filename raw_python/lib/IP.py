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

# import module
import socket
import struct

from .util import Packet
from ..samples.utils import get_ip

# Link type [required for wireshark pcap file]
LINKTYPE0 = 101
LINKTYPE1 = 228


class IPPacket(Packet):
    def __init__(self, dst='127.0.0.1', src=get_ip(), ver=4, vhl=5, dsc=0, ecn=0, tol=20, idf=1, flag_rsv=0, flag_dtf=0,
                 flag_mrf=0, frag_offset=0, ttl=64, proto=socket.IPPROTO_TCP, checksum=0):
        # load data into self container
        self.dst = dst
        self.src = src
        self.raw = None

        # ---- [Internet Protocol Version] ----
        self.ver = (ver << 4) + vhl
        # ---- [ Differentiate Service Field ]
        self.dfc = (dsc << 2) + ecn
        # ---- [ Total Length]
        self.tol = tol
        # ---- [ Identification ]
        self.idf = idf
        # ---- [ Flags ]
        self.flags = flag_rsv + flag_dtf + flag_mrf + frag_offset
        # ---- [ Total Length ]
        self.ttl = ttl
        # ---- [ Protocol ]
        self.protocol = proto
        # ---- [ Check Sum ]
        self.checksum = checksum
        # ---- [ Source Address ]
        self.source_address = socket.inet_aton(self.src)
        # ---- [ Destination Address ]
        self.destination_address = socket.inet_aton(self.dst)

        self.assemble_ipv4_fields()  # assemble all values
        self.checksum = self.calc_checksum(self.raw)  # Calculate Checksum
        self.assemble_ipv4_fields()  # assemble ipv4 fields

    def assemble_ipv4_fields(self):
        #  Size = 1+1+2+2+2+1+1+2+4+4

        self.raw = struct.pack('!BBHHhBB',
                               self.ver,  # IP Version
                               self.dfc,  # Differentiate Service Field
                               self.tol,  # Total Length
                               self.idf,  # Identification
                               self.flags,  # Flags
                               self.ttl,  # Time to leave
                               self.protocol,  # protocol
                               )

        self.raw = self.raw + struct.pack('H',
                                          self.checksum  # checksum
                                          )

        self.raw = self.raw + struct.pack('!4s4s',
                                          self.source_address,  # Source IP
                                          self.destination_address,  # Destination IP
                                          # self.padding
                                          )
        return self.raw


# IP Header Extraction
def parse_ip_header(data):
    unpacked = struct.unpack("!BBHHHBBH4s4s", data)
    _version = unpacked[0]
    _tos = unpacked[1]
    _total_length = unpacked[2]
    _identification = unpacked[3]
    _fragment_Offset = unpacked[4]
    _ttl = unpacked[5]
    _protocol = unpacked[6]
    _header_checksum = unpacked[7]
    _source_address = socket.inet_ntoa(unpacked[8])
    _destination_address = socket.inet_ntoa(unpacked[9])

    data = {'Version': _version,
            "Tos": _tos,
            "Total Length": _total_length,
            "Identification": _identification,
            "Fragment": _fragment_Offset,
            "TTL": _ttl,
            "Protocol": _protocol,
            "Header CheckSum": _header_checksum,
            "Source Address": _source_address,
            "Destination Address": _destination_address}
    return data


def load_ip(tcp=None, **kwargs):
    ip = IPPacket()
    length = len(tcp.raw) + len(ip.raw)
    kwargs['ip_tol'] = length
    return IPPacket()
