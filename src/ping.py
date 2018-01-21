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

# import module
import socket
import os
import random
import time
import select
from ICMP import ICMPPacket, ext_icmp_header



def catch_ping_reply(s, ID, time_sent, timeout=1):

    # create while loop
    while True:
        starting_time = time.time()     # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)
        
        # check if timeout
        if process[0] == []:
            return

        # receive packet
        rec_packet, addr = s.recvfrom(1024)

        # extract icmp packet from received packet 
        icmp = rec_packet[20:28]

        # extract information from icmp packet
        _id = ext_icmp_header(icmp)['id']

        # check identification
        if _id == ID:
            return ext_icmp_header(icmp)
    return


# 
def single_ping_request(s, addr=None):

    # Random Packet Id
    pkt_id = random.randrange(10000,65000)
    
    # Create ICMP Packet
    packet = ICMPPacket(icmp_id=pkt_id).raw

    # Send ICMP Packet
    while packet:
        sent = s.sendto(packet, (addr, 1))
        packet = packet[sent:]

    return pkt_id


def main():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # take Input
    addr = raw_input("[+] Enter Domain Name : ") or "www.google.com"
    
    # Request sent
    ID = single_ping_request(s, addr)

    # Catch Reply
    reply = catch_ping_reply(s, ID, time.time())

    if reply:
        print reply

    # close socket
    s.close()
    return

if __name__=='__main__':
    main()



