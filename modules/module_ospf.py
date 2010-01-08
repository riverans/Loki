#       module_ospf.py
#       
#       Copyright 2009 Daniel Mende <dmende@ernw.de>
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

import random
import socket
import struct
import os
import threading
import time

import dnet
import dpkt
import IPy

import gobject
import gtk

OSPF_VERSION = 2

SO_BINDTODEVICE	= 25

### HELPER_FUNKTIONS ###

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
    
def ospf_lsa_checksum(lsa):
    ''' Fletcher checksum for OSPF LSAs, returned as a 2 byte string.
    Give the whole LSA packet as argument.
    For details on the algorithm, see RFC 2328 chapter 12.1.7 and RFC 905 Annex B.
    '''

    CHKSUM_OFFSET = 16
    if len(lsa) < CHKSUM_OFFSET:
        raise Exception("LSA Packet too short (%s bytes)" % len(lsa))

    c0 = c1 = 0
    # Calculation is done with checksum set to zero
    lsa = lsa[:CHKSUM_OFFSET] + "\x00\x00" + lsa[CHKSUM_OFFSET+2:]
    for char in lsa[2:]:  #  leave out age
        c0 += ord(char)
        c1 += c0
    c0 %= 255
    c1 %= 255

    x = ((len(lsa) - CHKSUM_OFFSET - 1) * c0 - c1) % 255
    if (x <= 0):
        x += 255
    y = 510 - c0 - x
    if (y > 255):
        y -= 255
    #checksum = (x << 8) + y
    return chr(x) + chr(y)

def ospf_get_lsa_by_type(type):
    if type == ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS:
        return ospf_router_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS:
        return ospf_network_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_IP:
        return ospf_summary_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_SUMMARY_LINK_ASBR:
        return ospf_summary_link_advertisement()
    elif type == ospf_link_state_advertisement_header.TYPE_AS_EXTERNAL:
        return ospf_as_external_link_advertisement()
    else:
        raise Exception("Unknown LSA type '%x'" % (type))


### OSPF_PACKET_STRUCTURES ###

class ospf_header(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|   Version #   |     Type      |         Packet length         |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Router ID                            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                           Area ID                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|           Checksum            |             AuType            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Authentication                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Authentication                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    TYPE_HELLO = 1
    TYPE_DATABESE_DESCRIPTION = 2
    TYPE_LINK_STATE_REQUEST = 3
    TYPE_LINK_STATE_UPDATE = 4
    TYPE_LINK_STATE_ACK = 5

    AUTH_NONE = 0
    AUTH_SIMPLE = 1
    
    def __init__(self, type=None, id=None, area=None, auth_type=None, auth_data=None):
        self.version = OSPF_VERSION
        self.type = type
        self.id = id
        self.area = area
        self.auth_type = auth_type
        self.auth_data = auth_data

    def render(self, data):
        ret = "%s%s%s%s" % (struct.pack("!BBH", self.version, self.type, len(data) + 24),
                            self.id,
                            struct.pack("!LHHQ", self.area, 0, self.auth_type, self.auth_data),
                            data
                            )
        ret = ret[:12] + struct.pack("!H", ichecksum_func(ret)) + ret[14:]
        return ret

    def parse(self, data):
        (self.version, self.type, len, self.id, self.area, csum, self.auth_type, self.auth_data) = struct.unpack("!BBHLLHHQ", data[:24])
        return data[24:]

class ospf_hello(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Network Mask                           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|         HelloInterval         |    Options    |    Rtr Pri    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     RouterDeadInterval                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Designated Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                   Backup Designated Router                    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Neighbor                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    OPTION_TOS_CAPABILITY = 0x1
    OPTION_EXTERNAL_ROUTING_CAPABILITY = 0x2
    OPTION_CONTAINS_LSS = 0x10
    OPTION_DEMAND_CIRCUITS = 0x20
    OPTION_ZERO_BIT = 0x40

    def __init__(self, area=None, auth_type=None, auth_data=None, id=None, net_mask=None, hello_interval=None, options=None, router_prio=None, router_dead_interval=None, designated_router=None, backup_designated_router=None, neighbors=None):
        self.net_mask = net_mask
        self.hello_interval = hello_interval
        self.options = options
        self.router_prio = router_prio
        self.router_dead_interval = router_dead_interval
        self.designated_router = designated_router
        self.backup_designated_router = backup_designated_router
        self.neighbors = neighbors
        ospf_header.__init__(self, ospf_header.TYPE_HELLO, id, area, auth_type, auth_data)

    def render(self):
        neighbors = ""
        if self.neighbors:
            for i in self.neighbors:
                neighbors += i
        data = self.net_mask + struct.pack("!HBBLLL", self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) + neighbors
        return ospf_header.render(self, data)

    def parse(self, data):
        hello = ospf_header.parse(self, data)
        (self.net_mask, self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) = struct.unpack("!LHBBLLL", hello[:20])
        if len(hello) > 24:
            self.neighbors = []
            for i in xrange(24, len(hello)-4, 4):
                self.neighbors.append(hello[i:i+4])

class ospf_database_description(ospf_header):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|               MTU             |    Options    |0|0|0|0|0|I|M|MS
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     DD sequence number                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                             -+
    #|                             A                                 |
    #+-                 Link State Advertisement                    -+
    #|                           Header                              |
    #+-                                                             -+
    #|                                                               |
    #+-                                                             -+
    #|                                                               |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    FLAGS_INIT = 0x4
    FLAGS_MORE = 0x2
    FLAGS_MASTER_SLAVE = 0x1

    def __init__(self, area=None, auth_type=None, auth_data=None, id=None, mtu=None, options=None, flags=None, sequence_number=None):
        self.mtu = mtu
        self.options = options
        self.flags = flags
        self.sequence_number = sequence_number
        self.lsa_db = []
        ospf_header.__init__(self, ospf_header.TYPE_DATABESE_DESCRIPTION, id, area, auth_type, auth_data)
        
    def render(self, data):
        return ospf_header.render(self, struct.pack("!HBBL", self.mtu, self.options, self.flags, self.sequence_number) + data)

    def parse(self, data, parse_lsa=False):
        descr = ospf_header.parse(self, data)
        (self.mtu, self.options, self.flags, self.sequence_number) = struct.unpack("!HBBL", descr[:8])
        left = descr[8:]
        if parse_lsa:
            while left and len(left) >= 20:
                lsa = ospf_link_state_advertisement_header()
                lsa.parse(left[:20])
                self.lsa_db.append(lsa)
                left = left[20:]
        else:
            return left

class ospf_link_state_request(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          LS type                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Link State ID                           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     Advertising Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, ls_type=None, ls_id=None, advert_router=None):
        self.ls_type = ls_type
        self.ls_id = ls_id
        self.advert_router = advert_router
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_REQUEST, id, area, auth_type, auth_data)

    def render(self):
        data = struct.pack("!L", self.ls_type) + self.ls_id
        for i in self.advert_router:
            data += i
        return ospf_header.render(self, data)

    def parse(self, data):
        request = self.ospf_header.parse(data)
        (self.ls_type, self.ls_id) = struct.unpack("!LL", request)
        self.advert_router = []
        for i in xrange(8, len(request)-4, 4):
            self.advert_router.append(request[i,i+4])

class ospf_link_state_update(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      # advertisements                         |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                            +-+
    #|                  Link state advertisements                    |
    #+-                                                            +-+
    #|                              ...                              |

    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_UPDATE, id, area, auth_type, auth_data)

    def render(self):
        ret = struct.pack("!L", len(self.advertisements))
        for i in self.advertisements:
            ret += i.render()
        return ospf_header.render(self, ret)


    def parse(self, data):
        update = ospf_header.parse(self, data)
        (num,) = struct.unpack("!L", update[:4])
        left = update[4:]
        list = []
        for i in xrange(num):
            if not left:
                break
            advert = ospf_link_state_advertisement_header()
            advert.parse(left)
            lsa = ospf_get_lsa_by_type(advert.ls_type) 
            left = lsa.parse(left)
            list.append(lsa)
        self.advertisements = list[:]

class ospf_link_state_acknowledgment(ospf_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                                                               |
    #+-                                                             -+
    #|                             A                                 |
    #+-                 Link State Advertisement                    -+
    #|                           Header                              |
    #+-                                                             -+
    #|                                                               |
    #+-                                                             -+
    #|                                                               |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |


    def __init__(self, area=None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        ospf_header.__init__(self, ospf_header.TYPE_LINK_STATE_ACK, id, area, auth_type, auth_data)

    def render(self):
        ret = ""
        for i in self.advertisements:
            if type(i) == ospf_link_state_advertisement_header:
                ret += i.render()
            else:
                ret += ospf_link_state_advertisement_header.render(i, "")
        return ospf_header.render(self, ret)
        
    def parse(self, data):
        ack = self.ospf_header.parse(data)
        for i in xrange(0,len(ack),20):
            header = ospf_link_state_advertisement_header()
            header.parse(ack[i,i+20])
            self.advertisements.append(header)
            
class ospf_link_state_advertisement_header(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|            LS age             |    Options    |    LS type    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Link State ID                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     Advertising Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                     LS sequence number                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|         LS checksum           |             length            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    TYPE_ROUTER_LINKS = 1
    TYPE_NETWORK_LINKS = 2
    TYPE_SUMMARY_LINK_IP = 3
    TYPE_SUMMARY_LINK_ASBR = 4
    TYPE_AS_EXTERNAL = 5
    
    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None):
        self.ls_age = ls_age
        self.options = options
        self.ls_type = ls_type
        self.ls_id = ls_id
        self.advert_router = advert_router
        self.ls_seq = ls_seq
        self.csum = None

    def render(self, data):
        if self.csum:
            return struct.pack("!HBB", self.ls_age, self.options, self.ls_type) + self.ls_id + self.advert_router + struct.pack("!LHH", self.ls_seq, self.csum, 20 + len(data)) + data
        else:
            ret = struct.pack("!HBB", self.ls_age, self.options, self.ls_type) + self.ls_id + self.advert_router + struct.pack("!LHH", self.ls_seq, 0, 20 + len(data)) + data
            return ret[:16] + ospf_lsa_checksum(ret) + ret[18:]

    def parse(self, data):
        (self.ls_age, self.options, self.ls_type) = struct.unpack("!HBB", data[:4])
        self.ls_id = data[4:8]
        self.advert_router = data[8:12]
        (self.ls_seq, self.csum, self.len) = struct.unpack("!LHH", data[12:20])
        return data[20:]

class ospf_router_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|    0    |V|E|B|        0      |            # links            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                             Link                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                            Link[n]                            |

    FLAG_VIRTUAL_LINK_ENDPOINT = 0x0400
    FLAG_EXTERNAL = 0x0200
    FLAG_BORDER = 0x0100

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, flags=0x0, links=[]):
        self.flags = flags
        self.links = links
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = ""
        for i in self.links:
            ret += i.render()
        return ospf_link_state_advertisement_header.render(self, struct.pack("!HH", self.flags, len(self.links)) + ret)

    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.flags, num_links) = struct.unpack("!HH", adv[:4])
        left = adv[4:]
        for i in xrange(num_links):
            link = ospf_router_link_advertisement_link()
            left = link.parse(left)
            self.links.append(link)
        return left

class ospf_router_link_advertisement_link(object):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Link ID                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Link Data                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     Type      |     # TOS     |        TOS 0 metric           |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|      TOS      |        0      |            metric             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS[n]    |        0      |            metric             |

    TYPE_POINT_TO_POINT = 1
    TYPE_TRANSIT_NET = 2
    TYPE_STUB_NET = 3
    TYPE_VIRTUAL = 4

    LINK_ID_NEIGH_ID = 1
    LINK_ID_DESEG_ADDR = 2
    LINK_ID_NET_NUMBER = 3
    LINK_ID_NEIGH_ID2 = 4

    def __init__(self, id=None, data=None, type=None, tos_0=None, tos_n=[]):
        self.id = id
        self.data = data
        self.type = type
        self.tos_0 = tos_0
        self.tos_n = tos_n

    def render(self):
        ret = self.id + self.data + struct.pack("!BBH", self.type, len(self.tos_n), self.tos_0)
        for i in self.tos_n:
            ret += i.render()
        return ret

    def parse(self, data):
        self.id = data[:4]
        self.data = data[4:8]
        (self.type, len, self.tos_0) = struct.unpack("!BBH", data[8:12])
        left = data[12:]
        for i in xrange(len):
            tos = ospf_router_link_advertisement_tos()
            left = tos.parse(left)
        return left

class ospf_router_link_advertisement_tos(object):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|      TOS      |        0      |            metric             |

    def __init__(self, tos=None, metric=None):
        self.tos = tos
        self.metric = metric

    def render(self):
        return struct.pack("!BxH", self.tos, self.metric)

    def parse(self, data):
        (self.tos, self.metric) = struct.unpack("!BxH", data[:4])


class ospf_network_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                        Attached Router                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, router=[]):
        self.net_mask = net_mask
        self.router = router
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!L", self.net_mask)
        for i in self.router:
            ret += struct.pack("!L", i)
        return ospf_link_state_advertisement_header.render(self, ret)
        
    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.net_mask) = struct.unpack("!L", adv[:4])
        for i in xrange(4, len(adv), 4):
            router = struct.unpack("!L", adv[i:i+4])
            self.router.append(router)

class ospf_summary_link_advertisement(ospf_link_state_advertisement_header):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS       |                  metric                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, tos=[]):
        self.tos = tos
        self.metric = metric
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!L", self.net_mask)
        for i in self.tos:
            ret += i.render()
        return ospf_link_state_advertisement_header.render(self, ret)

    def parse(self, data):
        (self.net_mask) = struct.unpack("!L", data[:4])
        for i in xrange(4, len(data), 4):
            tos = ospf_summary_link_advertisement_tos()
            tos.parse(data[i,i+4])
            self.tos.append(tos)

class ospf_summary_link_advertisement_tos(object):

    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|     TOS       |                  metric                       |

    def __init__(self, tos=None, metric=None):
        self.tos = tos
        self.metric = metric

    def render(self):
        return struct.pack("!B3s", self.tos, self.metric)

    def parse(self, data):
        (self.tos, self.metric) = struct.unpack("!B3s", data)

class ospf_as_external_link_advertisement(ospf_link_state_advertisement_header):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                         Network Mask                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|E|    TOS      |                  metric                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Forwarding address                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      External Route Tag                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                              ...                              |

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, net_mask=None, tos=None, metric=None, forward_addr=None, external_route=None):
        self.net_mask = net_mask
        self.tos = tos
        self.metric = metric
        self.forward_addr = forward_addr
        self.external_route = external_route
        ospf_link_state_advertisement_header.__init__(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!LB3sL", self.net_mask, self.tos, self.metric, self.forward_addr)
        ret += self.external_route
        return ret

    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.net_mask, self.tos, self.metric, self.forward_addr) = struct.unpack("!LB3sL", adv[:12])
        self.external_route = adv[12:]
        
### OSPF_THREAD_CLASS ###

class ospf_thread(threading.Thread):
    STATE_HELLO = 1
    STATE_2WAY = 2
    STATE_EXSTART = 3
    STATE_EXCHANGE = 4
    STATE_LOADING = 5
    STATE_FULL = 6

    GLOBAL_STATE_INIT = 1
    GLOBAL_STATE_DONE = 2
    
    def __init__(self, parent, delay):
        self.parent = parent
        self.running = True
        self.hello = False
        self.delay = delay
        self.hello_count = 0
        self.state = self.GLOBAL_STATE_INIT
        threading.Thread.__init__(self)

    def send_multicast(self, data):
        ip_hdr = dpkt.ip.IP(    ttl=1,
                                p=dpkt.ip.IP_PROTO_OSPF,
                                src=self.parent.ip,
                                dst=dnet.ip_aton("224.0.0.5"),
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("01:00:5e:00:00:05"),
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))

    def send_unicast(self, mac, ip, data):
        ip_hdr = dpkt.ip.IP(    ttl=1,
                                p=dpkt.ip.IP_PROTO_OSPF,
                                src=self.parent.ip,
                                dst=ip,
                                data=data
                                )
        ip_hdr.len += len(ip_hdr.data)
        eth_hdr = dpkt.ethernet.Ethernet(   dst=mac,
                                            src=self.parent.mac,
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=str(ip_hdr)
                                            )
        self.parent.dnet.send(str(eth_hdr))


#~ +---+                                         +---+
#~ |RT1|                                         |RT2|
#~ +---+                                         +---+
#~ 
#~ Down                                          Down
                #~ Hello(DR=0,seen=0)
           #~ ------------------------------>
             #~ Hello (DR=RT2,seen=RT1,...)      Init
           #~ <------------------------------
#~ ExStart        D-D (Seq=x,I,M,Master)
           #~ ------------------------------>
               #~ D-D (Seq=y,I,M,Master)         ExStart
           #~ <------------------------------
#~ Exchange       D-D (Seq=y,M,Slave)
           #~ ------------------------------>
               #~ D-D (Seq=y+1,M,Master)         Exchange
           #~ <------------------------------
               #~ D-D (Seq=y+1,M,Slave)
           #~ ------------------------------>
                         #~ ...
                         #~ ...
                         #~ ...
               #~ D-D (Seq=y+n, Master)
           #~ <------------------------------
               #~ D-D (Seq=y+n, Slave)
 #~ Loading   ------------------------------>
                     #~ LS Request                Full
           #~ ------------------------------>
                     #~ LS Update
           #~ <------------------------------
                     #~ LS Request
           #~ ------------------------------>
                     #~ LS Update
           #~ <------------------------------
 #~ Full        

    def run(self):
        while(self.running):
            if self.parent.dnet:
                if self.hello and len(self.parent.neighbors) > 0:
                    #Build neighbor list
                    neighbors = []
                    for id in self.parent.neighbors:
                        neighbors.append(dnet.ip_aton(id))

                    if self.state == self.GLOBAL_STATE_INIT:
                        packet = ospf_hello(    self.parent.area,
                                                self.parent.auth_type,
                                                self.parent.auth_data,
                                                self.parent.ip,
                                                self.parent.mask,
                                                self.delay,
                                                ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                1,
                                                self.delay * 4,
                                                0,
                                                0,
                                                []
                                                )
                        self.state = self.GLOBAL_STATE_DONE
                        self.send_multicast(packet.render())

                    if self.hello_count == self.delay - 1:
                        self.hello_count = 0
                        #Multicast hello
                        packet = ospf_hello(    self.parent.area,
                                                self.parent.auth_type,
                                                self.parent.auth_data,
                                                self.parent.ip,
                                                self.parent.mask,
                                                self.delay,
                                                ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                1,
                                                self.delay * 4,
                                                self.parent.dr,
                                                self.parent.bdr,
                                                neighbors
                                                )
                        self.send_multicast(packet.render())
                    else:
                        self.hello_count += 1
                   
                    for id in self.parent.neighbors:
                        (iter, mac, ip, dbd, lsa, state, master, seq) = self.parent.neighbors[id]

                        if state == self.STATE_HELLO:
                            #Unicast hello
                            packet = ospf_hello(    self.parent.area,
                                                    self.parent.auth_type,
                                                    self.parent.auth_data,
                                                    self.parent.ip,
                                                    self.parent.mask,
                                                    self.delay,
                                                    ospf_hello.OPTION_TOS_CAPABILITY | (self.parent.options & ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY),
                                                    1,
                                                    self.delay * 4,
                                                    self.parent.dr,
                                                    self.parent.bdr,
                                                    neighbors
                                                    )
                            self.send_unicast(mac, ip, packet.render())                        
                        elif state == self.STATE_2WAY:
                            if dbd:
                                if master:
                                    packet = ospf_database_description( self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        self.parent.mtu,
                                                                        self.parent.options & ~ospf_hello.OPTION_CONTAINS_LSS | ospf_hello.OPTION_ZERO_BIT,
                                                                        ospf_database_description.FLAGS_MORE | ospf_database_description.FLAGS_MASTER_SLAVE | ospf_database_description.FLAGS_INIT,
                                                                        seq
                                                                        )
                                    self.send_unicast(mac, ip, packet.render(""))
                                    self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1)
                                else:
                                    #Learned DBD
                                    packet = ospf_database_description( self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        dbd.mtu,
                                                                        dbd.options & ~ospf_hello.OPTION_CONTAINS_LSS,
                                                                        dbd.flags & ~ospf_database_description.FLAGS_MASTER_SLAVE & ~ospf_database_description.FLAGS_INIT,
                                                                        dbd.sequence_number
                                                                        )
                                    self.send_unicast(mac, ip, packet.render(""))
                        #Exchange LSA State
                        elif state == self.STATE_EXSTART:
                            if master:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MASTER_SLAVE,
                                                                    seq
                                                                    )
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1)
                            else:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MORE,
                                                                    dbd.sequence_number
                                                                    )
                            lsa = ospf_link_state_advertisement_header( 92,
                                                                        ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY,
                                                                        ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                        self.parent.ip,
                                                                        self.parent.ip,
                                                                        1
                                                                        )
                            l_data = lsa.render("")
                            data = packet.render(l_data)
                            self.send_unicast(mac, ip, data)
                        elif state == self.STATE_EXCHANGE:
                            if master:
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    ospf_database_description.FLAGS_MASTER_SLAVE,
                                                                    seq
                                                                    )
                                self.send_unicast(mac, ip, packet.render(""))
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, lsa, state, master, seq + 1)
                            else:
                                #Ack DBD
                                packet = ospf_database_description( self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    self.parent.mtu,
                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_ZERO_BIT,
                                                                    0,
                                                                    dbd.sequence_number
                                                                    )
                                self.send_unicast(mac, ip, packet.render(""))
                        elif state == self.STATE_LOADING:
                            if master:
                                for lsa in dbd.lsa_db:
                                    packet = ospf_link_state_request(   self.parent.area,
                                                                        self.parent.auth_type,
                                                                        self.parent.auth_data,
                                                                        self.parent.ip,
                                                                        lsa.ls_type,
                                                                        lsa.ls_id,
                                                                        [lsa.advert_router]
                                                                        )
                                    data = packet.render()
                                    self.send_unicast(mac, ip, data)
                                    self.parent.neighbors[id] = (iter, mac, ip, dbd, [], state, False, seq)
                            else:
                                #LSUpdate
                                ipy = IPy.IP("%s/%s" % (dnet.ip_ntoa(self.parent.ip), dnet.ip_ntoa(self.parent.mask)), make_net=True)
                                links = [ ospf_router_link_advertisement_link(  dnet.ip_aton(str(ipy.net())),
                                                                                dnet.ip_aton(str(ipy.netmask())),
                                                                                ospf_router_link_advertisement_link.TYPE_POINT_TO_POINT,
                                                                                10
                                                                                ) ]
                                adverts = [ ospf_router_link_advertisement( 92,
                                                                            ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY,
                                                                            ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                            self.parent.ip,
                                                                            self.parent.ip,
                                                                            10,
                                                                            0,
                                                                            links
                                                                            ) ]
                                packet = ospf_link_state_update(    self.parent.area,
                                                                    self.parent.auth_type,
                                                                    self.parent.auth_data,
                                                                    self.parent.ip,
                                                                    adverts,
                                                                    )
                                self.send_unicast(mac, ip, packet.render())
                        elif state == self.STATE_FULL:
                            if len(lsa):
                                ack = ospf_link_state_acknowledgment(self.parent.area, self.parent.auth_type, self.parent.auth_data, self.parent.ip, lsa)
                                self.send_unicast(mac, ip, ack.render())
                                self.parent.neighbors[id] = (iter, mac, ip, dbd, [], state, master, seq)
                            for i in self.parent.nets:
                                (net, mask, type, active, removed) = self.parent.nets[i]
                                if active:
                                    def router_links(self, net, mask, mac, ip):
                                        links = [   ospf_router_link_advertisement_link(    dnet.ip_aton(net),
                                                                                            dnet.ip_aton(mask),
                                                                                            ospf_router_link_advertisement_link.TYPE_STUB_NET,
                                                                                            1
                                                                                            ),
                                                    ospf_router_link_advertisement_link(    struct.pack("!I", self.parent.dr),
                                                                                            self.parent.ip,
                                                                                            ospf_router_link_advertisement_link.TYPE_TRANSIT_NET,
                                                                                            1
                                                                                            ) ]
                                        adverts = [ ospf_router_link_advertisement( 92,
                                                                                    ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY | ospf_hello.OPTION_DEMAND_CIRCUITS,
                                                                                    ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS,
                                                                                    self.parent.ip,
                                                                                    self.parent.ip,
                                                                                    random.randint(11, 2^32),
                                                                                    0,
                                                                                    links
                                                                                    ) ]
                                        packet = ospf_link_state_update(    self.parent.area,
                                                                            self.parent.auth_type,
                                                                            self.parent.auth_data,
                                                                            self.parent.ip,
                                                                            adverts,
                                                                            )
                                        self.send_unicast(mac, ip, packet.render())

                                    def network_links(self, net, mask, mac, ip):
                                        pass
                                        
                                    {   ospf_link_state_advertisement_header.TYPE_ROUTER_LINKS : router_links,
                                        ospf_link_state_advertisement_header.TYPE_NETWORK_LINKS : network_links
                                        }[type](self, net, mask, mac, ip)
                                    self.parent.nets[i] = (net, mask, type, False, removed)
                                else:
                                    if removed:
                                        del self.parent.nets[i]
                                        del self.parent.network_liststore[i]
                        
            if not self.running:
                return
            time.sleep(1)

    def quit(self):
        self.running = False

### MODULE_CLASS ###

class mod_class(object):    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "ospf"
        self.gladefile = "modules/module_ospf.glade"
        self.neighbor_liststore = gtk.ListStore(str, str, str)
        self.network_liststore = gtk.ListStore(str, str, str)
        self.auth_type_liststore = gtk.ListStore(str, int)
        for i in dir(ospf_header):
            if i.startswith("AUTH_"):
                exec("val = ospf_header." + i)
                self.auth_type_liststore.append([i, val])
        self.net_type_liststore = gtk.ListStore(str, int)
        #~ for i in dir(ospf_link_state_advertisement_header):
        for i in [ "TYPE_ROUTER_LINKS" ]:       #, "TYPE_NETWORK_LINKS"
            if i.startswith("TYPE_"):
                exec("val = ospf_link_state_advertisement_header." + i)
                self.net_type_liststore.append([i, val])
        self.dnet = None
        self.area = 0
        self.auth_type = ospf_header.AUTH_NONE
        self.auth_data = 0
        self.neighbors = {}
        self.nets = {}
        self.dr = ""
        self.bdr = ""
        self.options = ospf_hello.OPTION_EXTERNAL_ROUTING_CAPABILITY
        self.mtu = 1500
        self.thread = ospf_thread(self, 10)
        self.filter = False

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.gladefile)
        dic = { "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled,
                "on_add_button_clicked" : self.on_add_button_clicked,
                "on_remove_button_clicked" : self.on_remove_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.neighbor_treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.neighbor_treeview.set_model(self.neighbor_liststore)
        self.neighbor_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("ID")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("STATE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.neighbor_treeview.append_column(column)

        self.network_treeview = self.glade_xml.get_widget("network_treeview")
        self.network_treeview.set_model(self.network_liststore)
        self.network_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Network")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.network_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Netmask")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.network_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.network_treeview.append_column(column)

        self.hello_tooglebutton = self.glade_xml.get_widget("hello_tooglebutton")
        self.area_entry = self.glade_xml.get_widget("area_entry")
        self.auth_type_combobox = self.glade_xml.get_widget("auth_type_combobox")
        self.auth_type_combobox.set_model(self.auth_type_liststore)
        self.auth_type_combobox.set_active(0)
        self.auth_data_entry = self.glade_xml.get_widget("auth_data_entry")

        self.network_entry = self.glade_xml.get_widget("network_entry")
        self.netmask_entry = self.glade_xml.get_widget("netmask_entry")
        self.net_type_combobox = self.glade_xml.get_widget("net_type_combobox")
        self.net_type_combobox.set_model(self.net_type_liststore)
        self.net_type_combobox.set_active(0)

        return self.glade_xml.get_widget("root")

    def set_log(self, log):
        self.log = log

    def shutdown(self):
        self.thread.quit()
        if self.filter:
            self.log("OSPF: Removing lokal packet filter for OSPF")
            os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
            self.filter = False

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)
        self.mask = dnet.ip_aton(mask)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    def set_int(self, interface):
        self.interface = interface

        self.thread.start()

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    def check_ip(self, ip):
        if ip.p == dpkt.ip.IP_PROTO_OSPF:
            return (True, False)
        return (False, False)

    def input_ip(self, eth, ip, timestamp):
        if ip.src != self.ip:
            #Multicast packet
            if ip.dst == dnet.ip_aton("224.0.0.5"):
                header = ospf_header()
                data = str(ip.data)
                header.parse(data[:24])
                if header.type == ospf_header.TYPE_HELLO:
                    hello = ospf_hello()
                    hello.parse(data)
                    id = dnet.ip_ntoa(header.id)
                    (ip_int,) = struct.unpack("!I", self.ip)
                    if id not in self.neighbors:
                        if socket.ntohl(header.id) < socket.ntohl(ip_int):
                            master = True
                        else:
                            master = False
                        #print "Local %s (%i) - Peer %s (%i) => Master " % (dnet.ip_ntoa(self.ip), socket.ntohl(ip_int), id, socket.ntohl(header.id)) + str(master)
                        iter = self.neighbor_liststore.append([dnet.ip_ntoa(ip.src), id, "HELLO"])
                        #                    (iter, mac,     src,    dbd, lsa, state,                 master, seq)
                        self.neighbors[id] = (iter, eth.src, ip.src, None, [], ospf_thread.STATE_HELLO, master, 1337)
                    elif self.thread.hello:
                        (iter, mac, src, dbd, lsa, state, master, seq) = self.neighbors[id]
                        if state == ospf_thread.STATE_HELLO:
                            self.neighbors[id] = (iter, src, src, dbd, lsa, ospf_thread.STATE_2WAY, master, seq)
                            self.neighbor_liststore.set_value(iter, 2, "2WAY")
                    self.dr = hello.designated_router
                    self.bdr = hello.backup_designated_router
                    self.options = hello.options
            #Unicast packet
            elif ip.dst == self.ip and self.thread.hello:
                header = ospf_header()
                data = str(ip.data)
                header.parse(data[:24])
                id = dnet.ip_ntoa(header.id)
                if id in self.neighbors:
                    (iter, mac, src, org_dbd, lsa, state, master, seq) = self.neighbors[id]
                    if header.type == ospf_header.TYPE_HELLO:
                        hello = ospf_hello()
                        hello.parse(data)
                        if state == ospf_thread.STATE_HELLO:
                            self.neighbors[id] = (iter, eth.src, ip.src, org_dbd, lsa, ospf_thread.STATE_2WAY, master, seq)
                            self.neighbor_liststore.set_value(iter, 2, "2WAY")
                    elif header.type == ospf_header.TYPE_DATABESE_DESCRIPTION:
                        dbd = ospf_database_description()
                        dbd.parse(data)
                        if state == ospf_thread.STATE_2WAY:                            
                            if not dbd.flags & ospf_database_description.FLAGS_INIT:
                                if master:
                                    #parse lsa header and store for master role in loading state
                                    dbd.parse(data, parse_lsa=True)
                                    if dbd.lsa_db != []:
                                        self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXSTART, master, seq)
                                        self.neighbor_liststore.set_value(iter, 2, "EXSTART")
                                else:
                                    self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXSTART, master, seq)
                                    self.neighbor_liststore.set_value(iter, 2, "EXSTART")
                            else:
                                self.neighbors[id] = (iter, mac, src, dbd, lsa, state, master, seq)
                        elif state == ospf_thread.STATE_EXSTART:
                            if not dbd.flags & ospf_database_description.FLAGS_MORE and not master:
                                self.neighbors[id] = (iter, mac, src, dbd, lsa, ospf_thread.STATE_EXCHANGE, master, seq)
                                self.neighbor_liststore.set_value(iter, 2, "EXCHANGE")
                            elif not dbd.flags and master:
                                self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_LOADING, master, seq)
                                self.neighbor_liststore.set_value(iter, 2, "LOADING")      
                    elif header.type == ospf_header.TYPE_LINK_STATE_REQUEST:
                        if state == ospf_thread.STATE_EXCHANGE:
                            self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_LOADING, master, seq)
                            self.neighbor_liststore.set_value(iter, 2, "LOADING")
                    elif header.type == ospf_header.TYPE_LINK_STATE_ACK:
                        if state == ospf_thread.STATE_LOADING:
                            self.neighbors[id] = (iter, mac, src, org_dbd, lsa, ospf_thread.STATE_FULL, master, seq)
                            self.neighbor_liststore.set_value(iter, 2, "FULL")
                    elif header.type == ospf_header.TYPE_LINK_STATE_UPDATE:
                        if state > ospf_thread.STATE_EXSTART:
                            if state < ospf_thread.STATE_LOADING:
                                state = ospf_thread.STATE_FULL
                                self.neighbor_liststore.set_value(iter, 2, "FULL")
                            update = ospf_link_state_update()
                            update.parse(data)
                            self.neighbors[id] = (iter, mac, src, org_dbd, update.advertisements, state, master, seq)

    # SIGNALS #

    def on_hello_togglebutton_toggled(self, btn):
        self.thread.hello = btn.get_active()
        if self.thread.hello:
            self.area_entry.set_property("sensitive", False)
            self.auth_type_combobox.set_property("sensitive", False)
            self.auth_data_entry.set_property("sensitive", False)
            if not self.filter:
                self.log("OSPF: Setting lokal packet filter for OSPF")
                os.system("iptables -A INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
                self.filter = True
        else:
            self.area_entry.set_property("sensitive", True)
            self.auth_type_combobox.set_property("sensitive", True)
            self.auth_data_entry.set_property("sensitive", True)
            if self.filter:
                self.log("OSPF: Removing lokal packet filter for OSPF")
                os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, dpkt.ip.IP_PROTO_OSPF))
                self.filter = False

    def on_add_button_clicked(self, btn):
        net = self.network_entry.get_text()
        mask = self.netmask_entry.get_text()
        type_name = self.net_type_liststore[self.net_type_combobox.get_active()][0]
        type = self.net_type_liststore[self.net_type_combobox.get_active()][1]
        iter = self.network_liststore.append([net, mask, type_name])
        self.nets[self.network_liststore.get_string_from_iter(iter)] = (net, mask, type, True, False)
        
    def on_remove_button_clicked(self, btn):
        select = self.network_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            (net, mask, type, active, removed) = self.nets[model.get_string_from_iter(iter)]
            self.nets[model.get_string_from_iter(iter)] = (net, mask, type, False, True)
            self.network_liststore.set_value(iter, 2, "REMOVED")