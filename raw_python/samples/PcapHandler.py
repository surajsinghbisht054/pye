#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#           Copyright 2018 Dept. CSE SUSTech
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


__author__ = 'Suraj Singh Bisht                  '  # Name Of Author
__credit__ = '[]                                 '  # Contributers Name
__contact__ = 'surajsinghbisht054@gmail.com       '  # Email
__copyright__ = 'Copyright 2018 Suraj Singh Bisht   '  # Copyright
__license__ = 'Apache 2.0                         '  # LICENSE
__Update__ = '2018-01-11 12:00:29.991758         '  # Last Update
__version__ = '0.1                                '  # Version
__maintainer__ = 'Suraj Singh Bisht                  '  # Project Current Maintainer
__status__ = 'Production                         '  # Project Status

# import module
import time

#     Pcap Global Header Format :
#                       ( magic number + 
#                         major version number + 
#                         minor version number + 
#                         GMT to local correction +
#                         accuracy of timestamps + 
#                         max length of captured #packets, in octets +
#                         data link type) 
#
#

PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '

# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


class Pcap:

    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')  # 4 + 2 + 2 + 4 + 4 + 4 + 4
        self.pcap_file.write(
            struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER,
                        PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))
        print
        "[+] Link Type : {}".format(link_type)

    def writelist(self, data=[]):
        for i in data:
            self.write(i)
        return

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


if __name__ == '__main__':

    # import modules
    import socket
    import struct
    import os

    # Create Socket 
    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((input("[+] YOUR_INTERFACE : "), 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    # Create Object
    p = Pcap('temp.pcap')

    while True:
        # Sniff Packet
        pkt = s.recvfrom(65565)

        # Save captured packets into pcap file
        p.write(pkt[0])

        # flush data
        p.pcap_file.flush()

    # close file
    p.close()
