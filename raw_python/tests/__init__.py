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

from raw_python import EtherPacket, IPPacket, ICMPPacket, TCPPacket, \
    parse_icmp_header, parse_ip_header, parse_eth_header
from raw_python.lib.IP import load_ip, LINKTYPE0


def ether_test():
    pkt = EtherPacket()
    print(parse_eth_header(pkt.raw))
    # return
    pkt1 = IPPacket()
    try:
        from ..samples.wsk import ShowPacket
        ShowPacket([pkt.raw + pkt1.raw], link_type=1)
    except:
        print("[+] Unable To Find pye.samples.wsk script.")
    return


def ip_test():
    pkt = IPPacket(flag_dtf=1)
    print(parse_ip_header(pkt.raw))

    try:
        from ..samples.wsk import ShowPacket
        ShowPacket(data=[pkt.raw], link_type=LINKTYPE0)
    except:
        print("[+] Unable To Find pye.samples.wsk script.")
    return


def icmp_test():
    icmp = ICMPPacket()
    print(parse_icmp_header(icmp.raw))
    ip = load_ip(tcp=icmp, ip_proto=socket.IPPROTO_ICMP)
    eth = EtherPacket(data=ip)

    try:
        from ..samples.wsk import ShowPacket
        pkt = eth.raw + ip.raw + icmp.raw
        ShowPacket([pkt], link_type=1)
    except Exception as e:
        print(e)
        print("[+] Unable To Find pye.samples.wsk script.")
    return


def tcp_test():
    tcp = TCPPacket()
    ip = load_ip(tcp=tcp)
    eth = EtherPacket(data=ip)

    try:
        from ..samples.wsk import ShowPacket
        pkt = eth.raw + ip.raw + tcp.raw
        ShowPacket([pkt], link_type=1)
    except Exception as e:
        print(e)
        print("[+] Unable To Find pye.samples.wsk script.")
    return


def udp_test():
    # TODO: complete this
    pass


if __name__ == '__main__':
    ether_test()
    ip_test()
    icmp_test()
    tcp_test()
    udp_test()
