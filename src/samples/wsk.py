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
import tempfile
import os
from PcapHandler import Pcap
import binascii

def hexdump(data):

	hexdata = binascii.hexlify(data)
	#print hexdata
	print "\t","_"*50,'\n'
	a=0
	for num, i in enumerate(range(0, len(hexdata)+32, 32)[1:]):
		line = hexdata[a:i]
		#print '='*60,line
		print "00{}0\t".format(num),
		x=0
		for j in range(0, len(line)+2, 2):
			print line[x:j].upper(),

			x=j
		print ''
		a=i
	print "\t","_"*50
	return



class ShowPacket:
	def __init__(self, data=[], **kwargs):
		self.data = data
		self.kwargs = kwargs
		self.showpacket()

	def showpacket(self):
		tmp = tempfile.mkstemp(suffix='.cap')
		pkt = Pcap(tmp[1], **self.kwargs)
		for i in self.data:
			pkt.write(i)
		pkt.close()
		cmd = 'wireshark \"{}\" '.format(tmp[1])
		print cmd
		os.system(cmd)
		return
