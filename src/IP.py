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
import struct
import binascii
from samples.utils import get_ip

# Link type [required for wireshark pcap file]
LINKTYPE0 = 101
LINKTYPE1 = 228

class IPPacket:
    def __init__(self, 
        # Parameters With Default Values

        dst='127.0.0.1',    # Destination IP
        src=get_ip(),#'192.168.1.101',    # Source IP
        
        # IP Version
        ip_ver = 4,                  
        ip_vhl = 5,            

        # Differentiate service field
        ip_dsc = 0,
        ip_ecn = 0,

        # Length
        ip_tol = 20,

        # Identification
        ip_idf = 1,

        # flags
        ip_flag_rsv = 0,
        ip_flag_dtf = 0,
        ip_flag_mrf = 0,
        ip_frag_offset = 0,

        # Time To live
        ip_ttl = 64,

        # Protocol
        ip_proto = socket.IPPROTO_TCP,

        # checksum
        ip_chk = 0,
        ):

        # load data into self container
        self.dst = dst
        self.src = src
        self.raw = None                   
        self._ip_ver = ip_ver
        self._ip_vhl = ip_vhl
        self._ip_dsc = ip_dsc
        self._ip_ecn = ip_ecn
        self._ip_tol = ip_tol
        self._ip_idf = ip_idf
        self._ip_flag_rsv = (ip_flag_rsv << 15)
        self._ip_flag_dtf = (ip_flag_dtf << 14)
        self._ip_flag_mrf = (ip_flag_mrf << 13)
        self._ip_frag_offset = (ip_frag_offset)
        self._ip_ttl = ip_ttl
        self._ip_proto = ip_proto
        self._ip_chk = ip_chk

        self.create_ipv4_feilds_list()       # create ipv4 fields object
        self.assemble_ipv4_feilds()          # assemble all values
        self.ip_chk = self.chksum(self.raw)  # Calculate Checksum
        self.assemble_ipv4_feilds()          # assembl ipv4 feilds



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

    def assemble_ipv4_feilds(self):
        #  Size = 1+1+2+2+2+1+1+2+4+4


        self.raw = struct.pack('!BBHHhBB' , 
            self.ip_ver,   # IP Version 
            self.ip_dfc,   # Differentiate Service Feild
            self.ip_tol,   # Total Length
            self.ip_idf,   # Identification
            self.ip_flg,   # Flags
            self.ip_ttl,   # Time to leave
            self.ip_proto, # protocol
            )
        
        self.raw = self.raw + struct.pack('H',
            self.ip_chk   # checksum
            )


        self.raw = self.raw + struct.pack('!4s4s',
            self.ip_saddr, # Source IP 
            self.ip_daddr,  # Destination IP
            #self.padding
            )
        return self.raw


    def create_ipv4_feilds_list(self):

        # ---- [Internet Protocol Version] ----
        self.ip_ver = (self._ip_ver << 4) + self._ip_vhl

        # ---- [ Differentiate Servic Field ]
        self.ip_dfc = (self._ip_dsc << 2 ) + self._ip_ecn

        # ---- [ Total Length]
        self.ip_tol = self._ip_tol

        # ---- [ Identification ]
        self.ip_idf = self._ip_idf

        # ---- [ Flags ]
        self.ip_flg = self._ip_flag_rsv + self._ip_flag_dtf + self._ip_flag_mrf  + self._ip_frag_offset
        
        # ---- [ Total Length ]
        self.ip_ttl = self._ip_ttl

        # ---- [ Protocol ]
        self.ip_proto = self._ip_proto

        # ---- [ Check Sum ]
        self.ip_chk = self._ip_chk

        # ---- [ Source Address ]
        self.ip_saddr = socket.inet_aton(self.src)

        # ---- [ Destination Address ]
        self.ip_daddr = socket.inet_aton(self.dst)

        return





# IP Header Extraction
def ext_ip_header(data):
    storeobj=struct.unpack("!BBHHHBBH4s4s", data)
    _version=storeobj[0] 
    _tos=storeobj[1]
    _total_length =storeobj[2]
    _identification =storeobj[3]
    _fragment_Offset =storeobj[4]
    _ttl =storeobj[5]
    _protocol =storeobj[6]    
    _header_checksum =storeobj[7]
    _source_address =socket.inet_ntoa(storeobj[8])
    _destination_address =socket.inet_ntoa(storeobj[9])

    data={'Version':_version,
        "Tos":_tos,
        "Total Length":_total_length,
        "Identification":_identification,
        "Fragment":_fragment_Offset,
        "TTL":_ttl,
        "Protocol":_protocol,
        "Header CheckSum":_header_checksum,
        "Source Address":_source_address,
        "Destination Address":_destination_address}
    return data







def LoadIP(tcp=None, **kwargs):
    ip = IPPacket(**kwargs)
    datalen = len(tcp.raw)+len(ip.raw)
    kwargs['ip_tol'] = datalen
    return IPPacket(**kwargs)


def main():
    pkt = IPPacket(ip_flag_dtf=1)
    print ext_ip_header(pkt.raw)

    try:
        from samples.wsk import ShowPacket
        ShowPacket(data=[pkt.raw], link_type=LINKTYPE0)
    except:
        print "[+] Unable To Find pye.samples.wsk script."
    return


if __name__=='__main__':
    main()
