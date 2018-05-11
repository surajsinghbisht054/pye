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


#!/usr/bin/python
import socket
import struct
import binascii
from IP import LoadIP
from Ether import EtherPacket
from samples import utils



TCP_STRUCTURE_FMT = '!HHLLBBHHH'

class TCPPacket:
    def __init__(self, 
        dport = 80, 
        sport = 65535, 
        dst='127.0.0.1', 
        src=utils.get_ip(),#'192.168.1.101', 
        data = '',
        seq = 0,
        ack_seq=0,
        flags = (0,0,0,0,0,0,0,0,1,0), # (rsv, noc, cwr, ecn, urg, ack, psh, rst, syn, fin) 
        ):
        self.dport = dport
        self.sport = sport
        self.src_ip = src
        self.dst_ip = dst
        self.ack = ack_seq
        self.seq = seq
        self.flags = flags
        self.data   = data
        self.raw = None
        self.create_tcp_feilds()
        self.assemble_tcp_feilds()
        #self.calculate_chksum()
        #self.reassemble_tcp_feilds()

    def assemble_tcp_feilds(self):
        self.raw = struct.pack('!HHLLBBHHH', # Data Structure Representation
            self.sport,       # Source Port
            self.dport,       # Destination Port
            self.tcp_seq,       # Sequence
            self.tcp_ack_seq,   # Acknownlegment Sequence
            self.tcp_hdr_len,   # Header Length
            self.tcp_flags ,    # TCP Flags
            self.tcp_wdw,       # TCP Windows
            self.tcp_chksum,    # TCP cheksum
            self.tcp_urg_ptr    # TCP Urgent Pointer
            )

        self.calculate_chksum() # Call Calculate CheckSum
        return


    def reassemble_tcp_feilds(self):
        self.raw = struct.pack(TCP_STRUCTURE_FMT, 
            self.tcp_src, 
            self.tcp_dst, 
            self.tcp_seq, 
            self.tcp_ack_seq, 
            self.tcp_hdr_len, 
            self.tcp_flags , 
            self.tcp_wdw,
            socket.htons(self.tcp_chksum), 
            self.tcp_urg_ptr
            )
        return

    def calculate_chksum(self):
        src_addr     = socket.inet_aton( self.src_ip )
        dest_addr    = socket.inet_aton( self.dst_ip )
        placeholder  = 0
        protocol     = socket.IPPROTO_TCP
        tcp_len      = len(self.raw) + len(self.data)
 
        psh = struct.pack('!4s4sBBH' , 
            src_addr , 
            dest_addr , 
            placeholder , 
            protocol , 
            tcp_len
            )

        psh = ''.join([psh, self.raw, self.data])

        self.tcp_chksum = self.chksum(psh)
        
        self.reassemble_tcp_feilds()
        
        return 


    def chksum(self, msg):
        s = 0       # Binary Sum

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if (i+1) < len(msg):
                a = ord(msg[i]) 
                b = ord(msg[i+1])
                s = s + (a+(b << 8))
            elif (i+1)==len(msg):
                s += ord(msg[i])
            else:
                raise "Something Wrong here"

        s = (s>>16) + (s & 0xffff)
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff

        return s

    def create_tcp_feilds(self):

        # ---- [ Source Port ]
        self.tcp_src = self.sport

        # ---- [ Destination Port ]
        self.tcp_dst = self.dport

        # ---- [ TCP Sequence Number]
        self.tcp_seq = self.seq

        # ---- [ TCP Acknowledgement Number]
        self.tcp_ack_seq = self.ack

        # ---- [ Header Length ]
        self.tcp_hdr_len = 80


        # ---- [ TCP Flags ]
        f = self.flags

        tcp_flags_rsv = (f[0] << 9)
        tcp_flags_noc = (f[1] << 8)
        tcp_flags_cwr = (f[2] << 7)
        tcp_flags_ecn = (f[3] << 6)
        tcp_flags_urg = (f[4] << 5)
        tcp_flags_ack = (f[5] << 4)
        tcp_flags_psh = (f[6] << 3)
        tcp_flags_rst = (f[7] << 2)
        tcp_flags_syn = (f[8] << 1)
        tcp_flags_fin = (f[9])

        self.tcp_flags = tcp_flags_rsv + tcp_flags_noc + tcp_flags_cwr + \
                                tcp_flags_ecn + tcp_flags_urg + tcp_flags_ack + \
                                tcp_flags_psh + tcp_flags_rst + tcp_flags_syn + tcp_flags_fin

        # ---- [ TCP Window Size ]
        self.tcp_wdw = 8192 #socket.htons (5840)#

        # ---- [ TCP CheckSum ]
        self.tcp_chksum = 0

        # ---- [ TCP Urgent Pointer ]
        self.tcp_urg_ptr = 0


        return





def main():
    tcp = TCPPacket()
    ip = LoadIP(tcp=tcp)
    eth = EtherPacket(data=ip)
    
    try:
        from samples.wsk import ShowPacket
        pkt = eth.raw+ip.raw+tcp.raw
        ShowPacket([pkt], link_type=1)
    except Exception as e:
        print e
        print "[+] Unable To Find pye.samples.wsk script."
    return


if __name__=='__main__':
    main()
