#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
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


__author__         = 'Suraj Singh Bisht                  ' #  Name Of Author
__credit__         = '[]                                 ' #  Contributers Name
__contact__        = 'surajsinghbisht054@gmail.com       ' #  Email
__copyright__      = 'Copyright 2018 Suraj Singh Bisht   ' #  Copyright
__license__        = 'Apache 2.0                         ' #  LICENSE
__Update__         = '2018-01-11 12:00:29.991758         ' #  Last Update 
__version__        = '0.1                                ' #  Version
__maintainer__     = 'Suraj Singh Bisht                  ' #  Project Current Maintainer
__status__         = 'Production                         ' #  Project Status

import socket
from struct import pack, unpack
from binascii import unhexlify, hexlify
from Ether import EtherPacket
from samples.wsk import ShowPacket, hexdump
from samples.utils import get_ip, get_mac

ARP_FORMAT = "!HHBBH6s4s6s4s"


class ARPPacket:
    def __init__(self, src_ip, dst_ip, src_mac):
        packet = ''
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[1],0x0001)
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[2],    0x0800)
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[3],    0x06)
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[4],    0x04)
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[5],    0x0001)
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[6:8],    unhexlify(src_mac)) 
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[8:10],    socket.inet_aton(src_ip))
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[10:12],    unhexlify("000000000000"))
        packet += pack(ARP_FORMAT[0]+ARP_FORMAT[12:14],    socket.inet_aton(dst_ip))
        self.raw = packet




def arp_request(ip, addr, mac):
    eth = EtherPacket(src=mac, protocol=0x0806).raw
    arp = ARPPacket(ip, addr, mac)
    pkt = eth+arp.raw
    return pkt




def main(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface,0))

    mac = get_mac(iface)
    ip = get_ip()
    addr = socket.gethostbyname('www.google.com')

    packet = arp_request(ip, addr, mac)    
    #from samples.wsk import ShowPacket

    #ShowPacket([arp_request(ip, addr, mac)])
    #print(ARP_FRAME)
    s.send(packet)
    #print repr(s.recv(1024))
    s.close()
    return


if __name__ == '__main__':
    main('wlx60e3271722fc')