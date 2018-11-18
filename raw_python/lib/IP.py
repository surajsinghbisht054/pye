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
        self._ver = ver
        self._vhl = vhl
        self._dsc = dsc
        self._ecn = ecn
        self._tol = tol
        self._idf = idf
        self._flag_rsv = (flag_rsv << 15)
        self._flag_dtf = (flag_dtf << 14)
        self._flag_mrf = (flag_mrf << 13)
        self._frag_offset = frag_offset
        self._ttl = ttl
        self._proto = proto
        self._checksum = checksum

        self.create_ipv4_feilds_list()  # create ipv4 fields object
        self.assemble_ipv4_fields()  # assemble all values
        self.ip_chk = self.calc_checksum(self.raw)  # Calculate Checksum
        self.assemble_ipv4_fields()  # assembl ipv4 feilds

    def assemble_ipv4_fields(self):
        #  Size = 1+1+2+2+2+1+1+2+4+4

        self.raw = struct.pack('!BBHHhBB',
                               self.ip_ver,  # IP Version
                               self.ip_dfc,  # Differentiate Service Feild
                               self.ip_tol,  # Total Length
                               self.ip_idf,  # Identification
                               self.ip_flg,  # Flags
                               self.ip_ttl,  # Time to leave
                               self.ip_proto,  # protocol
                               )

        self.raw = self.raw + struct.pack('H',
                                          self.ip_chk  # checksum
                                          )

        self.raw = self.raw + struct.pack('!4s4s',
                                          self.ip_saddr,  # Source IP
                                          self.ip_daddr,  # Destination IP
                                          # self.padding
                                          )
        return self.raw

    def create_ipv4_feilds_list(self):
        # ---- [Internet Protocol Version] ----
        self.ip_ver = (self._ver << 4) + self._vhl

        # ---- [ Differentiate Servic Field ]
        self.ip_dfc = (self._dsc << 2) + self._ecn

        # ---- [ Total Length]
        self.ip_tol = self._tol

        # ---- [ Identification ]
        self.ip_idf = self._idf

        # ---- [ Flags ]
        self.ip_flg = self._flag_rsv + self._flag_dtf + self._flag_mrf + self._frag_offset

        # ---- [ Total Length ]
        self.ip_ttl = self._ttl

        # ---- [ Protocol ]
        self.ip_proto = self._proto

        # ---- [ Check Sum ]
        self.ip_chk = self._checksum

        # ---- [ Source Address ]
        self.ip_saddr = socket.inet_aton(self.src)

        # ---- [ Destination Address ]
        self.ip_daddr = socket.inet_aton(self.dst)

        return


# IP Header Extraction
def parse_ip_header(data):
    storeobj = struct.unpack("!BBHHHBBH4s4s", data)
    _version = storeobj[0]
    _tos = storeobj[1]
    _total_length = storeobj[2]
    _identification = storeobj[3]
    _fragment_Offset = storeobj[4]
    _ttl = storeobj[5]
    _protocol = storeobj[6]
    _header_checksum = storeobj[7]
    _source_address = socket.inet_ntoa(storeobj[8])
    _destination_address = socket.inet_ntoa(storeobj[9])

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


def LoadIP(tcp=None, **kwargs):
    ip = IPPacket()
    datalen = len(tcp.raw) + len(ip.raw)
    kwargs['ip_tol'] = datalen
    return IPPacket()


def main():
    pkt = IPPacket(flag_dtf=1)
    print(parse_ip_header(pkt.raw))

    try:
        from ..samples.wsk import ShowPacket
        ShowPacket(data=[pkt.raw], link_type=LINKTYPE0)
    except:
        print("[+] Unable To Find pye.samples.wsk script.")
    return


if __name__ == '__main__':
    main()
