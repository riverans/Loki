#       module_arp.py
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

import dpkt
import dnet

import gobject
import gtk

class module_arp(threading.Thread):
    def __init__(self):
        self.sem = threading.Semaphore()
        threading.Thread.__init__(self)

    def run(self):
        pass

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "arp"
        self.gladefile = "modules/module_arp.glade"
        self.hosts_liststore = gtk.ListStore(str, str)
        self.upper_add_liststore = gtk.ListStore(str, str)
        self.lower_add_liststore = gtk.ListStore(str, str)
        self.spoof_treestore = gtk.TreeStore(gtk.gdk.Pixbuf, str, str)
        #self.thread = module_arp()

        self.hosts = {}
        self.upper_add = {}
        self.lower_add = {}

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.gladefile)
        dic = { "on_add_upper_button_clicked" : self.on_add_upper_button_clicked,
                "on_add_lower_button_clicked" : self.on_add_lower_button_clicked,
                "on_add_spoof_button_clicked" : self.on_add_spoof_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hosts_treeview = self.glade_xml.get_widget("hosts_treeview")
        self.hosts_treeview.set_model(self.hosts_liststore)
        self.hosts_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.hosts_treeview.append_column(column)

        self.upper_add_treeview = self.glade_xml.get_widget("upper_add_treeview")
        self.upper_add_treeview.set_model(self.upper_add_liststore)
        self.upper_add_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.upper_add_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.upper_add_treeview.append_column(column)

        self.lower_add_treeview = self.glade_xml.get_widget("lower_add_treeview")
        self.lower_add_treeview.set_model(self.lower_add_liststore)
        self.lower_add_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        column.set_title("MAC address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        self.lower_add_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP address")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.lower_add_treeview.append_column(column)

        self.spoof_treeview = self.glade_xml.get_widget("spoof_treeview")
        self.spoof_treeview.set_model(self.spoof_treestore)
        self.spoof_treeview.set_headers_visible(False)

        column = gtk.TreeViewColumn()
        render_pixbuf = gtk.CellRendererPixbuf()
        column.pack_start(render_pixbuf, expand=False)
        column.add_attribute(render_pixbuf, 'pixbuf', 0)
        self.spoof_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.spoof_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.spoof_treeview.append_column(column)

        return self.glade_xml.get_widget("root")

    def set_log(self, log):
        self.log = log

    def shutdown(self):
        pass

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            return (True, True)
        return (False, False)

    def input_eth(self, eth, timestamp):
        arp = dpkt.arp.ARP(str(eth.data))
        mac = dnet.eth_ntoa(str(eth.src))
        if mac not in self.hosts:
            ip = dnet.ip_ntoa(str(arp.spa))
            iter = self.hosts_liststore.append([mac, ip])
            self.hosts[mac] = (ip, iter)

    # SIGNALS #

    def on_add_upper_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, iter) = self.hosts[host]
                    iter = self.upper_add_liststore.append([host, ip])
                    self.upper_add[host] = (ip, iter)

    def on_add_lower_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, iter) = self.hosts[host]
                    iter = self.lower_add_liststore.append([host, ip])
                    self.lower_add[host] = (ip, iter)

    def on_add_spoof_button_clicked(self, data):
        if not len(self.upper_add):
            return
        if not len(self.lower_add):
            return
        parent = self.spoof_treestore.append(None, [data.render_icon(gtk.STOCK_NO, 1), "%i spoofs" % (len(self.upper_add) * len(self.lower_add)), None])
        for host_upper in self.upper_add:
            (ip_upper, iter_upper) = self.upper_add[host_upper]
            for host_lower in self.lower_add:
                (ip_lower, iter_lower) = self.lower_add[host_lower]
                self.spoof_treestore.append(parent, [None, ip_upper, ip_lower])
                self.lower_add_liststore.remove(iter_lower)
            self.host_lower = []
            self.upper_add_liststore.remove(iter_upper)
        self.upper_add = []
