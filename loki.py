#       loki.py
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

import sys
import os
import platform
import threading
import time

import gobject
import gtk
gtk.gdk.threads_init()

import dpkt
import pcap
import dnet

VERSION = "v0.1"
PLATFORM = platform.system()

class about_window(gtk.Window):
    def __init__(self, parent):
        gtk.Window.__init__(self)
        self.set_title("About")
        self.set_default_size(150, 70)
        self.set_property("modal", True)
        label = gtk.Label("This is %s version %s by Daniel Mende - dmende@ernw.de\nRunning on %s" % (parent.__class__.__name__, VERSION, PLATFORM))
        button = gtk.Button(gtk.STOCK_CLOSE)
        button.set_use_stock(True)
        button.connect_object("clicked", gtk.Widget.destroy, self)
        vbox = gtk.VBox()
        vbox.pack_start(label, True, True)
        vbox.pack_start(button, False, False)
        self.add(vbox)

class pcap_thread(threading.Thread):
    def __init__(self, parent, interface):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True
        self.interface = interface

    def run(self):
        p = pcap.pcapObject()
        #check to_ms = 100 for non linux
        p.open_live(self.interface, 1600, 0, 100)
        p.setnonblock(1)
        while self.running:
            
            p.dispatch(1, self.dispatch_packet)
            #try:
                #p.dispatch(1, self.dispatch_packet)
            #except Exception, e:
                #print e
            time.sleep(0.001)
        self.parent.log("Listen thread terminated")

    def quit(self):
        self.running = False

    def dispatch_packet(self, pktlen, data, timestamp):
        if not data:
            return
        eth = dpkt.ethernet.Ethernet(data)
        for (check, call) in self.parent.eth_checks:
            (ret, stop) = check(eth)
            if ret:
                call(eth, timestamp)
                if stop:
                    return
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = dpkt.ip.IP(str(eth.data))
            for (check, call) in self.parent.ip_checks:
                (ret, stop) = check(ip)
                if ret:
                    call(eth, ip, timestamp)
                    if stop:
                        return
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.tcp.TCP(str(ip.data))
                for (check, call) in self.parent.tcp_checks:
                    (ret, stop) = check(tcp)
                    if ret:
                        call(eth, ip, tcp, timestamp)
                        if stop:
                            return
                

class dnet_thread(threading.Thread):
    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface
        self.sem = threading.Semaphore()
        self.running = True
        self.eth = dnet.eth(interface)
        self.out = None

    def run(self):
        while self.running:
            self.sem.acquire()
            if self.out:
                self.eth.send(self.out)
                self.out = None
            self.sem.release()
            time.sleep(0.001)

    def quit(self):
        self.running = False

    def send(self, out):
        self.sem.acquire()
        self.out = out
        self.sem.release()
        time.sleep(0.001)

class codename_loki(object):
    def __init__(self):
        self.modules = {}
        self.msg_id = 0
        self.configured = False
        self.pcap_thread = None
        self.dnet_thread = None

        self.eth_checks = []
        self.ip_checks = []
        self.tcp_checks = []
        
        #gtk stuff
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)

        self.window.set_title(self.__class__.__name__)
        self.window.set_default_size(640, 480)

        #connect signal handlers
        self.window.connect("delete_event", self.delete_event)
        self.window.connect("destroy", self.destroy_event)

        self.toolbar = gtk.Toolbar()
        self.quit_button = gtk.ToolButton(gtk.STOCK_QUIT)
        self.quit_button.connect("clicked", self.on_quit_button_clicked)
        self.toolbar.insert(self.quit_button, 0)
        self.about_button = gtk.ToolButton(gtk.STOCK_ABOUT)
        self.about_button.connect("clicked", self.on_about_button_clicked)
        self.toolbar.insert(self.about_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.pref_button = gtk.ToolButton(gtk.STOCK_PREFERENCES)
        self.pref_button.connect("clicked", self.on_pref_button_clicked)
        #self.toolbar.insert(self.pref_button, 0)
        self.network_button = gtk.ToolButton(gtk.STOCK_NETWORK)
        self.network_button.connect("clicked", self.on_network_button_clicked)
        self.toolbar.insert(self.network_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.run_togglebutton = gtk.ToggleToolButton(gtk.STOCK_EXECUTE)
        self.run_togglebutton.connect("toggled", self.on_run_togglebutton_toogled)
        self.toolbar.insert(self.run_togglebutton, 0)

        self.vbox = gtk.VBox(False, 0)
        self.vbox.pack_start(self.toolbar, False, False, 0)
        self.notebook = gtk.Notebook()
        self.vbox.pack_start(self.notebook, True, True, 0)
        self.statusbar = gtk.Statusbar()
        self.vbox.pack_start(self.statusbar, False, False, 0)
        self.window.add(self.vbox)

    def main(self):
        print "This is %s version %s by Daniel Mende - dmende@ernw.de" % (self.__class__.__name__, VERSION)
        print "Running on %s" %(PLATFORM)

        self.load_modules()
        self.init_modules()

        self.window.show_all()
        
        gtk.main()

    def load_modules(self, path="./modules/"):
        #import the modules
        print "Loading modules..."
        sys.path.append(path)
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                (name, ext) = os.path.splitext(i)
                if ext == ".py":
                    try:
                        module = __import__(name)
                        print module
                        self.modules[name] = module.mod_class(self, PLATFORM)
                    except Exception, e:
                        print e

    def init_modules(self):
        for i in self.modules.keys():
            self.modules[i].set_log(self.log)
            root = self.modules[i].get_root()
            if root.get_parent():
                root.reparent(self.notebook)
                self.notebook.set_tab_label(root, tab_label=gtk.Label(self.modules[i].name))
            else:
                self.notebook.append_page(root, tab_label=gtk.Label(self.modules[i].name))
            root.set_property("sensitive", False)
            if "get_eth_checks" in dir(self.modules[i]):
                self.eth_checks.append(self.modules[i].get_eth_checks())
            if "get_ip_checks" in dir(self.modules[i]):
                self.ip_checks.append(self.modules[i].get_ip_checks())
            if "get_tcp_checks" in dir(self.modules[i]):
                self.tcp_checks.append(self.modules[i].get_tcp_checks())
            #self.modules[i].thread.start()

    def log(self, msg):
        #gtk.gdk.threads_enter()
        self.statusbar.push(self.msg_id, "[%i] %s" % (self.msg_id, msg))
        print "[%i] %s" % (self.msg_id, msg)
        #gtk.gdk.threads_leave()
        self.msg_id += 1

    def send_msg(self, msg):
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_INFO, gtk.BUTTONS_CLOSE, msg)
        label = gtk.Label(msg)
        dialog.vbox.pack_start(label, True, True, 0)
        dialog.run()
        dialog.destroy()

    ### EVENTS ###

    def on_run_togglebutton_toogled(self, btn):
        while not self.configured:
            self.on_network_button_clicked(None)
        if btn.get_property("active"):
            self.pcap_thread = pcap_thread(self, self.interface)
            self.pcap_thread.start()
            self.dnet_thread = dnet_thread(self.interface)
            self.dnet_thread.start()
            self.log("Listening on %s" % (self.interface))
            for i in self.modules:
                try:
                    if "set_ip" in dir(self.modules[i]):
                        self.modules[i].set_ip(self.ip, self.mask)
                except Exception, e:
                    print e
                try:
                    if "set_dnet" in dir(self.modules[i]):
                        self.modules[i].set_dnet(self.dnet_thread)
                except Exception, e:
                    print e
                try:
                    if "set_int" in dir(self.modules[i]):
                        self.modules[i].set_int(self.interface)
                except Exception, e:
                    print e
            for i in self.notebook:
                i.set_property("sensitive", True)
        else:
            for i in self.notebook:
                i.set_property("sensitive", False)
            self.pcap_thread.quit()
            self.pcap_thread = None
            self.dnet_thread.quit()
            self.dnet_thread = None

    def on_pref_button_clicked(self, data):
        pass
        
    def on_network_button_clicked(self, data):
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Select the interface to use")
        box = gtk.combo_box_new_text()
        devs = pcap.findalldevs()
        for (name, descr, addr, flags) in devs:
            if len(addr) > 1:
                (ip, mask, net, gw) = addr[1]
            else:
                ip = "no"
                mask = "address"
            if descr:
                line = " (%s %s) - %s" % (ip, mask, descr)
            else:
                line = " (%s %s)" % (ip, mask)
            box.append_text(name + line)
        box.set_active(0)
        dialog.vbox.pack_start(box)
        box.show()
        ret = dialog.run()
        dialog.destroy()
        if ret == gtk.RESPONSE_OK:
            model = box.get_model()
            active = box.get_active()
            self.interface = model[active][0].split(" ")[0]
            self.ip = model[active][0].split("(")[1].split(" ")[0]
            if self.ip == "no":
                self.ip = "0.0.0.0"
            self.mask = model[active][0].split(" ")[2].split(")")[0]
            if self.mask == "address":
                self.mask = "0"
            self.configured = True

    def on_about_button_clicked(self, data):
        window = about_window(self)
        window.show_all()

    def on_quit_button_clicked(self, data):
        self.delete_event(None, None)
        self.destroy_event(None)
    
    def delete_event(self, widget, event, data=None):
        for i in self.modules.keys():
            self.modules[i].shutdown()
        if self.pcap_thread:
            self.pcap_thread.quit()
        if self.dnet_thread:
            self.dnet_thread.quit()
        return False

    def destroy_event(self, widget, data=None):
        gtk.main_quit()

if __name__ == '__main__':
    app = codename_loki()
    app.main()
