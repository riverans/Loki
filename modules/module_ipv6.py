#       module_ipv6.py
#       
#       Copyright 2010 Daniel Mende <dmende@ernw.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import threading

import dnet

import gobject
import gtk
import gtk.glade
import struct

def ichecksum_func(data, sum=0):
    ''' Compute the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    '''
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in xrange(0,len(data),2):
        if i + 1 >= len(data):
            sum += ord(data[i]) & 0xFF
        else:
            w = ((ord(data[i]) << 8) & 0xFF00) + (ord(data[i+1]) & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum

    return sum & 0xFFFF

class ipv6_header(object):

   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |Version| Traffic Class |           Flow Label                  |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |         Payload Length        |  Next Header  |   Hop Limit   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +                         Source Address                        +
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +                      Destination Address                      +
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    def __init__(self, version=None, tclass=None, label=None, nh=None, hops=None, src=None, dst=None):
        self.version = version
        self.tclass = tclass
        self.label = label
        self.nh = nh
        self.hops = hops
        self.src = src
        self.dst = dst

    def parse(self, data):
        (ver_class_label, length, self.nh, self.hops, self.src, self.dst = struct.unpack("!IHBB16s16s", data[:40])
        self.version = ver_class_label >> 28
        self.tclass = (ver_class_label >> 20) & 0x0ff
        self.label = ver_class_label & 0x000fffff
        return data[40:]

    def render(self, data):
        ver_class_label = self.version << 28
        ver_class_label += self.tclass << 20
        ver_class_label += self.label
        return struct.pack("!IHBB16s16s", ver_class_label, len(data), self.nh, self.hops, self.src, self.dst) + data

class icmp6_header(object):
    
    #~  0                   1                   2                   3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |     Type      |     Code      |          Checksum             |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                                                               |
    #~ +                         Message Body                          +
    #~ |                                                               |
    
    def __init__(self, type=None, code=None):
        self.type = type
        self.code = code

    def parse(self, data):
        (self.type, self.code, self.csum) = struct.unpack("!BBH", data[:4])
        return data[4:]
        
    def render(self, data):
        ret = struct.pack("!BBH", self.type, self.code, 0) + data
        ret[3:4] = ichecksum_func(ret)
        return ret

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "ipv6"

    def start_mod(self):
        pass

    def shut_mod(self):
        pass

    def get_root(self):
        return gtk.Label("IPV6")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log
