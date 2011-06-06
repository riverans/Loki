#       module_8021Q.py
#       
#       Copyright 2011 Daniel Mende <dmende@ernw.de>
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
import dpkt

import gobject
import gtk
import gtk.glade

class mod_class(object):
    TAG_SOURCE_ROW = 0
    TAG_DESTINATION_ROW = 1
    TAG_TAG_ROW = 2
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "DOT1Q"
        self.gladefile = "/modules/module_DOT1Q.glade"
        self.tags = None
        self.tag_treestore = gtk.TreeStore(str, str, str)

    def start_mod(self):
        self.tags = {}

    def shut_mod(self):
        self.tag_treestore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = {}
        self.glade_xml.signal_autoconnect(dic)

        self.tag_treeview = self.glade_xml.get_widget("tag_treeview")
        self.tag_treeview.set_model(self.tag_treestore)
        self.tag_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Source")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TAG_SOURCE_ROW)
        self.tag_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Destination")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TAG_DESTINATION_ROW)
        self.tag_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Tag")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.TAG_TAG_ROW)
        self.tag_treeview.append_column(column)

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
            return (True, True)
        return (False, False)

    def input_eth(self, eth, timestamp):
        src = dnet.eth_ntoa(eth.src)
        dst = dnet.eth_ntoa(eth.dst)
        data = eth.data
        cur_tag = self.tags
        (tag, next_type) = struct.unpack("!HH", eth.data[:4])
        while next_type == dpkt.ethernet.ETH_TYPE_8021Q:
            id = tag & 0x1fff
            format_flag = (tag >> 12) & 0x1
            priority = (tag >> 13) & 0x7
            if id not in cur_tag:
                cur_tag[id] = { 'src'   :   src,
                                'dst'   :   dst
                                }
                self.log("DOT1Q: Got new tag %d: %s -> %s" % (id, src, dst))
            cur_tag = cur_tag[id]
            data = data[4:]

    #~ def get_config_dict(self):
        #~ return {    "foo" : {   "value" : self.foo,
                                #~ "type" : "int",
                                #~ "min" : 1,
                                #~ "max" : 10
                                #~ },
                    #~ "bar" : {   "value" : self.bar,
                                #~ "type" : "str",
                                #~ "min" : 1,
                                #~ "max" : 10000
                                #~ },
                    #~ "xxf" : {  "value" : self.sleep_time,
                                #~ "type" : "float",
                                #~ "min" : 1.0,
                                #~ "max" : -23.4321
                                #~ }
                    #~ }
    #~ def set_config_dict(self, dict):
        #~ if dict:
            #~ self.foo = dict["foo"]["value"]
            #~ self.bar = dict["bar"]["value"]
            #~ self.xxf = dict["xxf"]["value"]
