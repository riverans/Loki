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

import threading
import struct

import dnet

import gobject
import gtk

OSPF_VERSION = 2

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
    
    def __init__(self, type = None, id = None, area = None, auth_type=0, auth_data=0):
        self.version = OSPF_VERSION
        self.type = type
        self.id = id
        self.area = area
        self.auth_type = auth_type
        self.auth_data = auth_data

    def render(self, data):
        ret = struct.pack("!BBHLLHHQ", self.version, self.type, len(data) + 24, self.id, self.area, 0, self.auth_type, self.auth_data) + data
        ret[12:13] = ichcksum_func(ret)
        return ret

    def parse(self, data):
        (self.version, self.type, len, self.id, self.area, csum, self.auth_type, self.auth_data) = struct.unpack("!BBHLLHHQ", data[:24])
        return data[24:]

class osfp_hello(ospf_header):

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

    def __init__(self, area = None, auth_type=0, auth_data=0, id = None, net_mask = None, hello_interval = None, options = None, router_prio = None, router_dead_interval = None, designated_router = None, backup_designated_router = None, neighbors = None):
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
        if self.neighbors:
            neighbors = ""
            for i in self.neighbors:
                neighbors += strcut.pack("!L", i)
        return self.ospf_header.render(struct.pack("!LHBBLLL", self.net_mask, self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) + neighbors)

    def parse(self, data):
        hello = self.ospf_header.parse(data)
        (self.net_mask, self.hello_interval, self.options, self.router_prio, self.router_dead_interval, self.designated_router, self.backup_designated_router) = struct.unpack("!LHBBLLL", hello[:24])
        if len(hello) > 24:
            self.neighbors = []
            for i in xrange(24, len(hello)-4, 4):
                self.neighbors.append(hello[i:i+4])

class ospf_database_description(ospf_header):
    
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|       0       |       0       |    Options    |0|0|0|0|0|I|M|MS
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

    def __init__(self, area = None, auth_type=0, auth_data=0, id = None, options=None, flags=None, sequence_num=None):
        self.options = options
        self.flags = flags
        self.sequence_number = sequence_number
        ospf_header.__init__(self, ospf_header.TYPE_HELLO, id, area, auth_type, auth_data)
        
    def render(self, data):
        return self.ospf_header.render(struct.pack("!xxBBL", self.options, self.flags, self.sequence_number) + data)

    def parse(self, data):
        descr = self.ospf_header.parse(data)
        (self.options, self.flags, self.sequence_number) = struct.unpack("!xxBBL", descr)

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

    def __init__(self, area = None, auth_type=0, auth_data=0, ls_type=None, ls_id=None, advert_router=None):
        self.ls_type = ls_type
        self.ls_id = ls_id
        self.advert_router = advert_router
        ospf_header.__init__(self, ospf_header.TYPE_HELLO, id, area, auth_type, auth_data)

    def render(self):
        data = self.ospf_header.render(struct.pack("!LL", self.ls_type, self.ls_id))
        for i in self.advert_router:
            data += struct.pack("!L", i)
        return data

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

    def __init__(self, area = None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        opsf_header.__init__(self, ospf_header.TYPE_LINK_STATE_UPDATE, id, area, auth_type, auth_data)

    def render(self):
        ret = struct.pack("!L", len(self.advertisements))
        for i in self.advertisements:
            ret += i.render()
        return osfp_hello.render(self, ret)


    def parse(self, data):
        update = self.ospf_header.parse(data)
        (num) = struct.unpack("!F", update[:4])
        left = update[4:]
        for i in xrange(num):
            advert = ospf_advertisment()
            left = advert.parse(left)
            self.advertisments.append(advert)

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


    def __init__(self, area = None, auth_type=0, auth_data=0, id=None, advertisements=[]):
        self.advertisements = advertisements
        opsf_header.__init__(self, ospf_header.TYPE_LINK_STATE_UPDATE, id, area, auth_type, auth_data)

    def render(sel, data):
        for i in self.advertisements:
            ret += i.render()
        return osfp_hello.render(self, ret)
        
    def parse(self, data):
        update = self.ospf_header.parse(data)
        for i in xrange(0,len(update),20):
            header = ospf_link_state_advertisement_header()
            header.parse(update[i,i+20])
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
        self.len= len(data)

    def render(sel, data):
        ret = struct.pack("!HBBLLLHH", self.ls_age, self.options, self.ls_type, self.ls_id, self.advert_router, 0, 20 + self.len) + data
        ret[14:16] = ichecksum_func(ret)
        return ret

    def parse(self, data):
        (self.ls_age, self.options, self.ls_type, self.ls_id, self.advert_router, self.csum, self.len) = struct.unpack("!HBBLLLHH", data[:20])
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

    def __init__(self, ls_age=None, options=None, ls_type=None, ls_id=None, advert_router=None, ls_seq=None, flags=None,links=[]):
        self.flags = flags
        self.links = links
        ospf_link_state_advertisement_header(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!LL", self.flags, len(self.links))
        for i in self.links:
            ret += i.render()
        return ospf_link_state_advertisement_header.render(self, ret)

    def parse(self, data):
        adv = ospf_link_state_advertisement_header.parse(self, data)
        (self.flags, num_links) = struct.unpack("!HH", adv[:4])
        left = adv[4:]
        for i in num_links:
            link = ospf_router_link_advertisement_link()
            left = link.parse(left)
            self.links.append(link)

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
        ret = struct.pack("!LLBBH", self.id, self.data, self.type, len(self.tos_n), self.tos_0)
        for i in self.tos_n:
            ret += i.render()
        return ret

    def parse(self, data):
        (self.id, self.data, self.type, len, self.tos_0) = struct.unpack("!LLBBH", data[:12])
        for i in xrange(0, len*4, 4):
            tos = ospf_router_link_advertisement_tos()
            tos.parse(data[12+i:12+i*4])

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
        ospf_link_state_advertisement_header(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!L", self.net_mask)
        for i in self.router:
            ret += struct.pack("!L", i)
        return ospf_link_state_advertisement_header.render(self, ret)
        
    def parse(self, data):
        (self.net_mask) = struct.unpack("!L", data[:4])
        for i in xrange(4, len(data), 4):
            router = struct.unpack("!L", data[i:i+4])
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
        ospf_link_state_advertisement_header(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

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
        ospf_link_state_advertisement_header(self, ls_age, options, ls_type, ls_id, advert_router, ls_seq)

    def render(self):
        ret = struct.pack("!LB3sL", self.net_mask, self.tos, self.metric, self.forward_addr)
        ret += self.external_route.render()
        return ret

    def parse(self, data):
        (self.net_mask, self.tos, self.metric, self.forward_addr) = struct.unpack("!LB3sL", data)
        #self.external_route = OSPF_EXTERNAL_ROUTE_METRIC_SOME_WHAT
        
### OSPF_THREAD_CLASS ###

class ospf_hello_thread(threading.Thread):
    def __init__(self):
        pass

### MODULE_CLASS ###

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "ospf"
        self.gladefile = "modules/module_ospf.glade"
        self.neighbor_liststore = gtk.ListStore(str, str)

        self.neighbors = {}

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.gladefile)
        dic = { "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled
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


        return self.glade_xml.get_widget("root")

    def set_log(self, log):
        self.log = log

    def shutdown(self):
        pass

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    def check_ip(self, ip):
        if ip.dst == dnet.ip_aton("224.0.0.5"):
            return (True, False)
        return (False, False)

    def input_ip(self, eth, ip, timestamp):
        header = ospf_header()
        data = str(ip.data)
        header.parse(data[:24])
        if header.type == ospf_header.TYPE_HELLO:
            id = dnet.ip_ntoa(header.id)
            if id not in self.neighbors:
                self.neighbors[id] = None
                self.neighbor_liststore.append([dnet.ip_ntoa(ip.src), id])

    # SIGNALS #

    def on_hello_togglebutton_toggled(self, btn):
        pass
