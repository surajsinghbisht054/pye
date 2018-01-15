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



# import modules
import struct
import socket
from IP import LoadIP
from Ether import EtherPacket

# Header is type (8), code (8), checksum (16), id (16), sequence (16)
#    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
ICMP_STRUCTURE_FMT = 'bbHHh'
ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.

ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
    }


class ICMPPacket:
    def __init__(self,
        icmp_type = ICMP_ECHO_REQUEST,
        icmp_code = 0,
        icmp_chks = 0,
        icmp_id   = 1,
        icmp_seq  = 1,
        data      ='' ,
        ):

        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_chks = icmp_chks
        self.icmp_id   = icmp_id
        self.icmp_seq  = icmp_seq
        self.data      = data
        self.raw = None
        self.create_icmp_field()

    def create_icmp_field(self):
        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )

        # calculate checksum
        self.icmp_chks = self.chksum(self.raw+self.data)

        self.raw = struct.pack(ICMP_STRUCTURE_FMT,
            self.icmp_type,
            self.icmp_code,
            self.icmp_chks,
            self.icmp_id,
            self.icmp_seq,
            )

        return 

    def chksum(self, msg):
        s = 0       # Binary Sum

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):

            a = ord(msg[i]) 
            b = ord(msg[i+1])
            s = s + (a+(b << 8))
            
        
        # One's Complement
        s = s + (s >> 16)
        s = ~s & 0xffff

        return s


# ICMP HEADER Extraction
def ext_icmp_header(data):
    icmph=struct.unpack(ICMP_STRUCTURE_FMT, data)
    data={
    'type'  :   icmph[0],
    "code"  :   icmph[1],
    "checksum": icmph[2],
    'id'    :   icmph[3],
    'seq'   :   icmph[4],
    }
    return data

def main():
    icmp = ICMPPacket()
    print ext_icmp_header(icmp.raw)
    ip = LoadIP(tcp=icmp, ip_proto=socket.IPPROTO_ICMP)
    eth = EtherPacket(data=ip)

    
    try:
        from samples.wsk import ShowPacket
        pkt = eth.raw +ip.raw+icmp.raw
        ShowPacket([pkt], link_type=1)
    except Exception as e:
        print e
        print "[+] Unable To Find pye.samples.wsk script."
    return


if __name__=='__main__':
    main()
