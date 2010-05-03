#       module_mpls.py
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


import struct
import threading

import loki_bindings

import dnet
import dpkt

import gobject
import gtk
import gtk.glade

class mod_class(object):
    PEER_SRC_ROW = 0
    PEER_DST_ROW = 1
    PEER_LABEL_ROW = 2
    PEER_EXP_ROW = 3
    PEER_TTL_ROW = 4
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "mpls"
        self.gladefile = "/modules/module_mpls.glade"
        self.peer_treestore = gtk.TreeStore(str, str, str, str, str)

    def start_mod(self):
        self.peers = {}

    def shut_mod(self):
        self.peer_treestore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { 
                }
        self.glade_xml.signal_autoconnect(dic)

        self.peer_treeview = self.glade_xml.get_widget("peer_treeview")
        self.peer_treeview.set_model(self.peer_treestore)
        self.peer_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("SRC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_SRC_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("DST")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_DST_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("LABEL")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_LABEL_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("EXP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_EXP_ROW)
        self.peer_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("TTL")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.PEER_TTL_ROW)
        self.peer_treeview.append_column(column)

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_MPLS:
            return (True, True)
        return (False, False)

    def input_eth(self, eth, timestamp):
        src = dnet.eth_ntoa(eth.src)
        dst = dnet.eth_ntoa(eth.dst)
        data = eth.data
        src_dst = src + ":" + dst
        if src_dst not in self.peers:
            iter = self.peer_treestore.append(None, [src, dst, "", "", ""])
            dict = self.parse_label(data, iter)
            self.peers[src_dst] = (iter, dict)
            self.log("MPLS: Got new MPLS communication: %s->%s" % (src, dst))
        else:
            (iter, dict) = self.peers[src_dst]
            self.parse_label(data, iter, dict)

    def parse_label(self, data, iter, dict={}, depth=0):
        (label, exp, bos, ttl) = self.get_label(data)
        if label in dict:
            (child, sub_dict) = dict[label]
        else:
            pad = " " * depth
            child = self.peer_treestore.append(iter, ["", "", pad + str(label), pad + str(exp), pad + str(ttl)])
            sub_dict = {}
            
        if bos == 0:
            self.parse_label(data[4:], child, sub_dict, depth + 1)

        dict[label] = (child, sub_dict)
        return dict

    def get_label(self, data):
        (data,) = struct.unpack("!L", data[:4])
        label = (data & 0xfffff000) >> 12
        exp = (data & 0x00000e00) >> 9
        bos = (data & 0x00000100) >> 8
        ttl = (data & 0x000000ff)
        return (label, exp, bos, ttl)
