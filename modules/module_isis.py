#       module_isis.py
#       
#       Copyright 2013 Daniel Mende <dmende@ernw.de>
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

import struct
import threading
import time

import dnet
import dpkt

import gobject
import gtk
import gtk.glade

ISIS_VERSION = 1
ISIS_PROTOCOL_DISCRIMINATOR = 0x83
ISIS_ALL_L1_IS_MAC = "01:80:c2:00:00:14"
ISIS_ALL_L2_IS_MAC = "01:80:c2:00:00:15"

class isis_pdu_header(object):
    TYPE_L1_HELLO = 15
    TYPE_L2_HELLO = 16
    TYPE_P2P_HELLO = 17
    TYPE_L1_LINK_STATE = 18
    TYPE_L2_LINK_STATE = 20
    TYPE_L1_COMPLETE_SEQUENCE = 24
    TYPE_L2_COMPLETE_SEQUENCE = 25
    TYPE_L1_PARTIAL_SEQUENCE = 26
    TYPE_L2_PARTIAL_SEQUENCE = 27
    
    def __init__(self, sys_id_length=None, pdu_type=None, eco=None, user_eco=None):
        self.sys_id_length = sys_id_length
        self.pdu_type = pdu_type
        self.eco = eco
        self.user_eco = user_eco
        
    def render(self, data):
        return struct.pack("!BBBBBBBB", ISIS_PROTOCOL_DISCRIMINATOR, len(data)+8, ISIS_VERSION, self.sys_id_length,
                                self.pdu_type, ISIS_VERSION, self.eco, self.user_eco) + data
    
    def parse(self, data):
        (self.header_length, self.sys_id_length, self.pdu_type, self.eco, self.user_eco) = struct.unpack("!xBxBBxBB", data[:8])
        return data[8:] 

class isis_pdu_lan_hello(isis_pdu_header):
    def __init__(self, layer=None, circuit_type=None, source_id=None, hold_timer=None, priority=None, lan_id=None, tlvs=[], mtu=1497):
        self.circuit_type = circuit_type
        self.source_id = source_id
        self.hold_timer = hold_timer
        self.priority = priority
        self.lan_id = lan_id
        self.tlvs = tlvs
        self.mtu = mtu
        if layer is not None:
            isis_pdu_header.__init__(self, 0, layer, 0, 0)
        else:
            isis_pdu_header.__init__(self)
    
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        while len(tlv_data) < self.mtu - 27:
            t = isis_tlv(isis_tlv.TYPE_PADDING, "\x00" * min(255, self.mtu - 27 - 2 - len(tlv_data)))
            tlv_data += t.render()
        return isis_pdu_header.render(self, struct.pack("!B6sHHB7s", self.circuit_type, self.source_id, self.hold_timer,
                                len(tlv_data) + 27, self.priority, self.lan_id)) + tlv_data
        
    def parse(self, data):
        data = isis_pdu_header.parse(self, data)
        (self.circuit_type, self.source_id, self.hold_timer, self.pdu_length, self.priority, self.lan_id) = struct.unpack("!B6sHHB7s", data[:19])
        self.tlvs = parse_tlvs(data[19:])

class isis_pdu_link_state(isis_pdu_header):
    def __init__(self, layer=None, lifetime=None, lsp_id=None, sequence=None, type_block=None, tlvs=[]):
        self.lifetime = lifetime
        self.lsp_id = lsp_id
        self.sequence = sequence
        self.type_block = type_block
        self.tlvs = tlvs
        if layer is not None:
            isis_pdu_header.__init__(self, 0, layer, 0, 0)
        else:
            isis_pdu_header.__init__(self)
        
    def render(self):
        tlv_data = ""
        for t in self.tlvs:
            tlv_data += t.render()
        return isis_pdu_header.render(self, struct.pack("!HH8sIHB", len(tlv_data) + 27, self.lifetime, self.lsp_id,
                                self.sequence, 0, self.type_block)) + tlv_data
        
    def parse(self, data):
        data = isis_pdu_header.parse(self, data)
        (self.pdu_length, self.lifetime, self.lsp_id, self.sequence, self.csum, self.type_block) = struct.unpack("!HH8sIHB", data[:19])
        self.tlvs = parse_tlvs(data[19:])
    
def get_tlv(pdu, ttype):
    for i in pdu.tlvs:
        if i.t == ttype:
            return i

def parse_tlvs(data):
    tlvs = []
    while len(data) > 0:
        tlv = isis_tlv()
        data_new = tlv.parse(data)
        if tlv.t == isis_tlv.TYPE_AREA_ADDRESS:
            tlv = isis_tlv_area_address()
            data = tlv.parse(data)
        else:
            data = data_new
        tlvs.append(tlv)
    return tlvs
        
class isis_tlv(object):
    TYPE_AREA_ADDRESS =     0x01
    TYPE_IS_NEIGHBOURS =    0x06
    TYPE_PADDING =          0x08
    TYPE_IP_INT_REACH =     0x80
    TYPE_PROTOCOL_SUPPORT = 0x81
    TYPE_IP_INT_ADDRESS =   0x84
    TYPE_HOSTNAME =         0x89
    TYPE_RESTART_SIGNALING= 0xd3
    
    def __init__(self, t=None, v=None):
        self.t = t
        self.v = v
    
    def render(self, data=None):
        if data is None:
            data = self.v
        return struct.pack("!BB", self.t, len(data)) + data
    
    def parse(self, data):
        (self.t, self.l) = struct.unpack("!BB", data[:2])
        self.v = data[2:2+self.l]
        return data[2+self.l:]

class isis_tlv_area_address(isis_tlv):
    def __init__(self, addresses = []):
        self.addresses = addresses
        isis_tlv.__init__(self, isis_tlv.TYPE_AREA_ADDRESS)
        
    def __repr__(self):
        return ", ".join([a.encode("hex") for a in self.addresses])
    
    def render(self):
        data = ""
        for i in self.addresses:
            data += struct.pack("!B", len(i)) + i
        return isis_tlv.render(self, data)
        
    def parse(self, data):
        data = isis_tlv.parse(self, data)
        while len(self.v) > 0:
            (alen, ) = struct.unpack("!B", self.v[:1])
            self.addresses.append(self.v[1:1+alen])
            self.v = self.v[1+alen:]
        return data
        
class isis_thread(threading.Thread):
    def __init__(self, parent):
        self.parent = parent
        self.running = True
        self.hello = False
        self.hello_count = 0
        threading.Thread.__init__(self)
    
    def send_multicast(self, data):
        llc = "\xfe\xfe\x03" + data
        eth_hdr = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(ISIS_ALL_L1_IS_MAC if self.parent.layer == isis_pdu_header.TYPE_L1_HELLO else ISIS_ALL_L2_IS_MAC),
                                            src=self.parent.mac,
                                            type=len(llc),
                                            data=llc
                                            )
        self.parent.dnet.send(str(eth_hdr))
    
    def run(self):
        while(self.running):
            if self.parent.dnet:
                if self.hello and len(self.parent.neighbors) > 0:
                    
                    tlvs = [    isis_tlv(isis_tlv.TYPE_PROTOCOL_SUPPORT, "\xcc"), #IP
                                isis_tlv(isis_tlv.TYPE_AREA_ADDRESS, "\x03\x01\x00\x02"), #get from gui
                                isis_tlv(isis_tlv.TYPE_IP_INT_ADDRESS, self.parent.ip),
                                isis_tlv(isis_tlv.TYPE_RESTART_SIGNALING, "\x00\x00\x00"),
                                isis_tlv(isis_tlv.TYPE_IS_NEIGHBOURS, "".join(self.parent.neighbors.keys())),
                                ]
                    
                    hello = isis_pdu_lan_hello(self.parent.layer, 3, "loki4u", 30, 64, "loki4u\x01", tlvs, self.parent.mtu - 3 - 14)
                    self.send_multicast(hello.render())
            
            if not self.running:
                return
            time.sleep(self.parent.sleep_time)
    
    def quit(self):
        self.running = False
        
class mod_class(object):
    NEIGH_IP_ROW = 0
    NEIGH_ID_ROW = 1
    NEIGH_LAYER_ROW = 2
    NEIGH_STATE_ROW = 3
    NEIGH_AUTH_ROW = 4
    NEIGH_CRACK_ROW = 5

    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "isis"
        self.group = "ROUTING"
        self.gladefile = "/modules/module_isis.glade"
        self.neighbor_treestore = gtk.TreeStore(str, str, str, str, str, str)
        self.neighbors = {}
        self.layer_liststore = gtk.ListStore(str, int)
        self.layer_liststore.append(["Layer 1", isis_pdu_header.TYPE_L1_HELLO])
        self.layer_liststore.append(["Layer 2", isis_pdu_header.TYPE_L2_HELLO])
        self.layer_liststore.append(["Peer to Peer", isis_pdu_header.TYPE_P2P_HELLO])
        self.dnet = None
#        self.filter = False
        self.thread = None
        self.mtu = 1514
#        self.delay = 10
        self.sleep_time = 1


    def start_mod(self):
        self.thread = isis_thread(self)
        
        self.thread.start()

    def shut_mod(self):
        if self.thread:
            self.thread.quit()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled,
            }
        self.glade_xml.signal_autoconnect(dic)

        self.neighbor_treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.neighbor_treeview.set_model(self.neighbor_treestore)
        self.neighbor_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_IP_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("ID")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_ID_ROW)
        self.neighbor_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("AREA")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_LAYER_ROW)
        self.neighbor_treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("STATE")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.NEIGH_STATE_ROW)
        #~ self.neighbor_treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("AUTH")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.NEIGH_AUTH_ROW)
        #~ self.neighbor_treeview.append_column(column)
        #~ column = gtk.TreeViewColumn()
        #~ column.set_title("CRACK")
        #~ render_text = gtk.CellRendererText()
        #~ column.pack_start(render_text, expand=True)
        #~ column.add_attribute(render_text, 'text', self.NEIGH_CRACK_ROW)
        #~ self.neighbor_treeview.append_column(column)
        
        self.layer_combobox = self.glade_xml.get_widget("layer_combobox")
        self.layer_combobox.set_model(self.layer_liststore)
        self.layer_combobox.set_active(0)
        
        self.hello_tooglebutton = self.glade_xml.get_widget("hello_tooglebutton")
        self.area_entry = self.glade_xml.get_widget("area_entry")

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.ip = dnet.ip_aton(ip)
        self.mask = dnet.ip_aton(mask)

    def set_dnet(self, dnet):
        self.dnet = dnet
        self.mac = dnet.eth.get()

    def set_int(self, interface):
        self.interface = interface

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.dst == dnet.eth_aton(ISIS_ALL_L1_IS_MAC) or eth.dst == dnet.eth_aton(ISIS_ALL_L2_IS_MAC):
            return (True, True)
        return (False, False)
        
    def input_eth(self, eth, timestamp):
        if eth.src != self.mac:
            data = str(eth.data)[3:]
            if eth.dst == dnet.eth_aton(ISIS_ALL_L1_IS_MAC) or eth.dst == dnet.eth_aton(ISIS_ALL_L2_IS_MAC):
                header = isis_pdu_header()
                header.parse(data)
                if header.pdu_type == isis_pdu_header.TYPE_L1_HELLO or \
                        header.pdu_type == isis_pdu_header.TYPE_L2_HELLO:
                    hello = isis_pdu_lan_hello()
                    hello.parse(data)
                    if eth.src not in self.neighbors:
                        cur = {}
                        cur["hello"] = hello
                        cur["iter"] = self.neighbor_treestore.append(None, [
                                                                        dnet.eth_ntoa(eth.src), 
                                                                        hello.source_id.encode("hex"), 
                                                                        str(get_tlv(hello, isis_tlv.TYPE_AREA_ADDRESS)), 
                                                                        "HELLO", 
                                                                        "...", 
                                                                        "..."
                                                                    ])
                        cur["lsps"] = {}
                        
                        self.log("ISIS: Got new peer %s" % (dnet.eth_ntoa(eth.src)))
                        self.neighbors[eth.src] = cur
                elif header.pdu_type == isis_pdu_header.TYPE_L1_LINK_STATE or \
                        header.pdu_type == isis_pdu_header.TYPE_L2_LINK_STATE:
                    if eth.src in self.neighbors:
                        cur = self.neighbors[eth.src]
                        ls = isis_pdu_link_state()
                        ls.parse(data)
                        if ls.lsp_id in cur["lsps"]:
                            self.neighbor_treestore.remove(cur["lsps"][ls.lsp_id]["iter"])
                            del cur["lsps"][ls.lsp_id]
                        new = {}
                        new["iter"] = self.neighbor_treestore.append(cur["iter"], [
                                                                        "",
                                                                        ls.lsp_id.encode("hex"),
                                                                        "",
                                                                        "",
                                                                        "",
                                                                        ""
                                                                    ])
                        cur["lsps"][ls.lsp_id] = new
                        tlv = get_tlv(ls, isis_tlv.TYPE_IP_INT_REACH)
                        if not tlv is None:
                            prefixes = tlv.v
                            while len(prefixes) > 0:
                                self.neighbor_treestore.append(new["iter"], [
                                                                    "",
                                                                    "",
                                                                    dnet.ip_ntoa(prefixes[4:8]) + " / " + dnet.ip_ntoa(prefixes[8:12]),
                                                                    "",
                                                                    "",
                                                                    ""
                                                                ])
                                prefixes = prefixes[12:]
                    
    #SIGNALS
    
    def on_hello_togglebutton_toggled(self, btn):
        if btn.get_active():
            self.layer_combobox.set_property("sensitive", False)
            self.area_entry.set_property("sensitive", False)
            self.layer = self.layer_liststore[self.layer_combobox.get_active()][1]
            self.log("ISIS: Hello thread activated")
        else:
            self.area_entry.set_property("sensitive", True)
            self.layer_combobox.set_property("sensitive", True)
            self.log("ISIS: Hello thread deactivated")
        self.thread.hello = btn.get_active()

    def get_config_dict(self):
        return {    "mtu" : {   "value" : self.mtu,
                                "type" : "int",
                                "min" : 1,
                                "max" : 1514
                                },
                    }
    def set_config_dict(self, dict):
        if dict:
            self.mtu = dict["mtu"]["value"]
