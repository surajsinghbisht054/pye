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

#import modules
import struct            # struct module
import binascii          # binary ASCII module
from IP import IPPacket  # Class To Create IPv4 Packet. (Check Code_IPv4_packet_using_socket Link)  
from samples import utils




# Ethernet II (DIX) Protocol Types

ETH_P_LOOP     = 0x0060    # hernet Loopback packet
ETH_P_PUP      = 0x0200    # rox PUP packet     
ETH_P_PUPAT    = 0x0201    # rox PUP Addr Trans packet  
ETH_P_IP       = 0x0800    # ternet Protocol packet 
ETH_P_X25      = 0x0805    # ITT X.25           
ETH_P_ARP      = 0x0806    # dress Resolution packet    
ETH_P_IEEEPUP  = 0x0a00    # rox IEEE802.3 PUP packet 
ETH_P_IEEEPUPAT= 0x0a01    # rox IEEE802.3 PUP Addr Trans packet 
ETH_P_DEC      = 0x6000    # C Assigned proto           
ETH_P_DNA_DL   = 0x6001    # C DNA Dump/Load            
ETH_P_DNA_RC   = 0x6002    # C DNA Remote Console       
ETH_P_DNA_RT   = 0x6003    # C DNA Routing              
ETH_P_LAT      = 0x6004    # C LAT                      
ETH_P_DIAG     = 0x6005    # C Diagnostics              
ETH_P_CUST     = 0x6006    # C Customer use             
ETH_P_SCA      = 0x6007    # C Systems Comms Arch       
ETH_P_TEB      = 0x6558    # ans Ether Bridging     
ETH_P_RARP     = 0x8035    # verse Addr Res packet  
ETH_P_ATALK    = 0x809B    # pletalk DDP        
ETH_P_AARP     = 0x80F3    # pletalk AARP       
ETH_P_8021Q    = 0x8100    # 2.1Q VLAN Extended Header  
ETH_P_IPX      = 0x8137    # X over DIX         
ETH_P_IPV6     = 0x86DD    # v6 over bluebook       
ETH_P_PAUSE    = 0x8808    # EE Pause frames. See 802.3 31B 
ETH_P_SLOW     = 0x8809    # ow Protocol. See 802.3ad 43B 
ETH_P_WCCP     = 0x883E    # b-cache coordination protocol



# Simple Ethernet Frame Class
class EtherPacket:
    def __init__(self, dst='ff:ff:ff:ff:ff:ff', src='', protocol=ETH_P_IP, data=''):
        self.dst = dst                # Destination MAC
        if not src:
            interface = utils.all_interfaces()[::-1][0][0]
            src=utils.get_mac(interface=interface)
        self.src = src                # Source MAC
        self.protocol = protocol      # Protocol Types
        self.raw = None               # Raw Data
        self.data = data
        self.assemble_eth_feilds()

    def assemble_eth_feilds(self):
        # Assemble All Feilds Of Ether Packet

        self.raw = struct.pack(
                        "!6s6sH",
                        binascii.unhexlify(self.dst.replace(":","")),
                        binascii.unhexlify(self.src.replace(":","")),
                        self.protocol)
        return self.raw #''.join([self.raw, self.data])


# Ethernet Header
def ext_eth_header(data):
    storeobj=data
    storeobj=struct.unpack("!6s6sH",storeobj)
    destination_mac=binascii.hexlify(storeobj[0])
    source_mac=binascii.hexlify(storeobj[1])
    eth_protocol=storeobj[2]
    data={"Destination Mac":destination_mac,
    "Source Mac":source_mac,
    "Protocol":eth_protocol}
    return data





def main():
    pkt = EtherPacket()
    print ext_eth_header(pkt.raw)
    #return
    pkt1 = IPPacket()
    try:
        from samples.wsk import ShowPacket
        ShowPacket([pkt.raw+pkt1.raw], link_type=1)
    except:
        print "[+] Unable To Find pye.samples.wsk script."
    return


if __name__=='__main__':
    main()
