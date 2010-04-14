#!/usr/bin/env python

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
import signal
import threading
import time
import traceback
import string

import gobject
import gtk
gtk.gdk.threads_init()

import dpkt
import pcap
import dnet

DEBUG = True

VERSION = "v0.2"
PLATFORM = platform.system()

MODULE_PATH="/modules"
DATA_DIR="."

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
        buttonbox = gtk.HButtonBox()
        buttonbox.pack_start(button)
        vbox = gtk.VBox()
        vbox.pack_start(label, True, True, 0)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

class log_window(gtk.Window):
    def __init__(self, textbuffer):
        gtk.Window.__init__(self)
        self.set_title("Log")
        self.set_default_size(300, 400)
        textview = gtk.TextView(textbuffer)
        textview.set_editable(False)
        button = gtk.Button(gtk.STOCK_CLOSE)
        button.set_use_stock(True)
        button.connect_object("clicked", gtk.Widget.destroy, self)
        buttonbox = gtk.HButtonBox()
        buttonbox.pack_start(button)
        scrolledwindow = gtk.ScrolledWindow()
        scrolledwindow.add(textview)
        scrolledwindow.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        vbox = gtk.VBox()
        vbox.pack_start(scrolledwindow, True, True, 0)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

class preference_window(gtk.Window):
    def __init__(self, parent):
        self.par = parent
        gtk.Window.__init__(self)
        self.set_title("Preferences")
        self.set_default_size(150, 70)
        #self.set_property("modal", True)
        self.module_liststore = gtk.ListStore(str, bool, bool)
        notebook = gtk.Notebook()
        module_treeview = gtk.TreeView()
        module_treeview.set_model(self.module_liststore)
        module_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Module")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 0)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Enabled")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.connect('toggled', self.toggle_callback, self.module_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, "active", 1)
        module_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Reset")
        render_toggle = gtk.CellRendererToggle()
        render_toggle.set_property('activatable', True)
        render_toggle.set_property('radio', True)
        render_toggle.connect('toggled', self.reset_callback, self.module_liststore)
        column.pack_start(render_toggle, expand=False)
        column.add_attribute(render_toggle, 'active', 2)
        module_treeview.append_column(column)
        
        notebook.append_page(module_treeview, tab_label=gtk.Label("Modules"))
        vbox = gtk.VBox(False, 0)
        vbox.pack_start(notebook, True, True, 0)
        buttonbox = gtk.HButtonBox()
        close = gtk.Button(gtk.STOCK_CLOSE)
        close.set_use_stock(True)
        close.connect_object("clicked", self.close_button_clicked, None)
        buttonbox.pack_start(close)
        vbox.pack_start(buttonbox, False, False, 0)
        self.add(vbox)

        for i in self.par.modules.keys():
            (module, enabled) = self.par.modules[i]
            self.module_liststore.append([i, enabled, False])

    def toggle_callback(self, cell, path, model):
        model[path][1] = not model[path][1]
        if model[path][1]:
            self.par.init_module(model[path][0])
        else:
            self.par.shut_module(model[path][0])

    def reset_callback(self, cell, path, model):
        model[path][2] = not model[path][2]
        if cell:
            gobject.timeout_add(750, self.reset_callback, None, path, model)
            cur = self.par.notebook.get_current_page()
            old_pos = self.par.shut_module(model[path][0])
            self.par.load_module(model[path][0], model[path][1])
            (module, enabled) = self.par.modules[model[path][0]]
            if enabled:
                self.par.init_module(model[path][0], old_pos)
                if old_pos == cur:
                    self.par.notebook.set_current_page(cur)
            return False
        
    def close_button_clicked(self, arg):
        gtk.Widget.destroy(self)

class pcap_thread(threading.Thread):
    def __init__(self, parent, interface):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True
        self.interface = interface

    def run(self):
        p = pcap.pcapObject()
        #check to_ms = 100 for non linux
        p.open_live(self.interface, 1600, 1, 100)
        p.setnonblock(1)
        while self.running:
            try:
                p.dispatch(1, self.dispatch_packet)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60

            time.sleep(0.001)
        self.parent.log("Listen thread terminated")

    def quit(self):
        self.running = False

    def dispatch_packet(self, pktlen, data, timestamp):
        if not data:
            return
        eth = dpkt.ethernet.Ethernet(data)
        for (check, call, name) in self.parent.eth_checks:
            (ret, stop) = check(eth)
            if ret:
                call(eth, timestamp)
                if stop:
                    return
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = dpkt.ip.IP(str(eth.data))
            for (check, call, name) in self.parent.ip_checks:
                (ret, stop) = check(ip)
                if ret:
                    call(eth, ip, timestamp)
                    if stop:
                        return
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = dpkt.tcp.TCP(str(ip.data))
                for (check, call, name) in self.parent.tcp_checks:
                    (ret, stop) = check(tcp)
                    if ret:
                        call(eth, ip, tcp, timestamp)
                        if stop:
                            return
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = dpkt.udp.UDP(str(ip.data))
                for (check, call, name) in self.parent.udp_checks:
                    (ret, stop) = check(udp)
                    if ret:
                        call(eth, ip, udp, timestamp)
                        if stop:
                            return

class pcap_thread_offline(pcap_thread):
    def __init__(self, parent, filename):
        self.filename = filename
        pcap_thread.__init__(self, parent, "null")

    def run(self):
        p = pcap.pcapObject()
        #check to_ms = 100 for non linux
        p.open_offline(self.filename)
        while self.running:
            try:
                if not p.dispatch(1, self.dispatch_packet):
                    self.running = False
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
        self.parent.log("Read thread terminated")

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
        self.fw = None
        self.data_dir = DATA_DIR

        self.eth_checks = []
        self.ip_checks = []
        self.tcp_checks = []
        self.udp_checks = []

        self.module_active = []
        
        #gtk stuff
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)

        self.window.set_title(self.__class__.__name__)
        self.window.set_default_size(640, 480)

        #connect signal handlers
        self.window.connect("delete_event", self.delete_event)
        self.window.connect("destroy", self.destroy_event)

        self.toolbar = gtk.Toolbar()
        self.toolbar.set_tooltips(True)
        self.quit_button = gtk.ToolButton(gtk.STOCK_QUIT)
        self.quit_button.connect("clicked", self.on_quit_button_clicked)
        self.quit_button.set_tooltip_text("QUIT")
        self.toolbar.insert(self.quit_button, 0)
        self.about_button = gtk.ToolButton(gtk.STOCK_ABOUT)
        self.about_button.connect("clicked", self.on_about_button_clicked)
        self.about_button.set_tooltip_text("ABOUT")
        self.toolbar.insert(self.about_button, 0)
        self.log_button = gtk.ToolButton(gtk.STOCK_EDIT)
        self.log_button.connect("clicked", self.on_log_button_clicked)
        self.log_button.set_tooltip_text("LOG")
        self.toolbar.insert(self.log_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.pref_button = gtk.ToolButton(gtk.STOCK_PREFERENCES)
        self.pref_button.connect("clicked", self.on_pref_button_clicked)
        self.pref_button.set_tooltip_text("PREFERENCES")
        self.toolbar.insert(self.pref_button, 0)
        self.network_button = gtk.ToolButton(gtk.STOCK_NETWORK)
        self.network_button.connect("clicked", self.on_network_button_clicked)
        self.network_button.set_tooltip_text("NETWORK")
        self.toolbar.insert(self.network_button, 0)
        self.toolbar.insert(gtk.SeparatorToolItem(), 0)
        self.open_togglebutton = gtk.ToggleToolButton(gtk.STOCK_OPEN)
        self.open_togglebutton.connect("toggled", self.on_open_togglebutton_toggled)
        self.open_togglebutton.set_tooltip_text("OPEN")
        self.toolbar.insert(self.open_togglebutton, 0)
        self.run_togglebutton = gtk.ToggleToolButton(gtk.STOCK_EXECUTE)
        self.run_togglebutton.connect("toggled", self.on_run_togglebutton_toogled)
        self.run_togglebutton.set_tooltip_text("RUN")
        self.toolbar.insert(self.run_togglebutton, 0)

        self.vbox = gtk.VBox(False, 0)
        self.vbox.pack_start(self.toolbar, False, False, 0)
        self.notebook = gtk.Notebook()
        self.vbox.pack_start(self.notebook, True, True, 0)
        self.statusbar = gtk.Statusbar()
        self.vbox.pack_start(self.statusbar, False, False, 0)
        self.window.add(self.vbox)

        self.log_textbuffer = gtk.TextBuffer()
        self.log_window = log_window(self.log_textbuffer)

    def main(self):
        print "This is %s version %s by Daniel Mende - dmende@ernw.de" % (self.__class__.__name__, VERSION)
        print "Running on %s" %(PLATFORM)

        self.load_all_modules()
        self.init_all_modules()
        self.window.show_all()
        
        gtk.main()

    def load_all_modules(self, path=DATA_DIR + MODULE_PATH):
        #import the modules
        if DEBUG:
            print "Loading modules..."
        sys.path.append(path)
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                (name, ext) = os.path.splitext(i)
                if ext == ".py":
                    self.load_module(name, True)
            elif os.path.isdir(os.path.join(path, i)):
                pass

    def init_all_modules(self):
        if DEBUG:
            print "Initialising modules..."
        for i in self.modules:
            self.init_module(i)
    
    def load_module(self, module, enabled=True):
        if DEBUG:
            print "load %s, enabled %i" % (module, enabled)
        try:
            mod = __import__(module)
            if DEBUG:
                print mod
            self.modules[module] = (mod.mod_class(self, PLATFORM), enabled)
        except Exception, e:
            print e
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60

    def init_module(self, module, pos=-1):
        if DEBUG:
            print "init %s" % module
        (mod, enabled) = self.modules[module]
        mod.set_log(self.log)
        root = mod.get_root()
        if root.get_parent():
            root.reparent(self.notebook)
            self.notebook.set_tab_label(root, gtk.Label(mod.name))
            self.notebook.reorder_child(root, pos)
        else:
            self.notebook.insert_page(root, gtk.Label(mod.name), pos)
        root.set_property("sensitive", False)
        if "get_eth_checks" in dir(mod):
            (check, call) = mod.get_eth_checks()
            self.eth_checks.append((check, call, mod.name))
        if "get_ip_checks" in dir(mod):
            (check, call) = mod.get_ip_checks()
            self.ip_checks.append((check, call, mod.name))
        if "get_tcp_checks" in dir(mod):
            (check, call) = mod.get_tcp_checks()
            self.tcp_checks.append((check, call, mod.name))
        if "get_udp_checks" in dir(mod):
            (check, call) = mod.get_udp_checks()
            self.udp_checks.append((check, call, mod.name))
        if self.run_togglebutton.get_active():
            self.start_module(module)
            root.set_property("sensitive", True)
        else:
            root.set_property("sensitive", False)
        self.modules[module] = (mod, True)

    def start_module(self, module):
        (mod, en) = self.modules[module]
        if en:
            try:
                if "set_ip" in dir(mod):
                    mod.set_ip(self.ip, self.mask)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if self.dnet_thread:
                    if "set_dnet" in dir(mod):
                        mod.set_dnet(self.dnet_thread)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if "set_fw" in dir(mod):
                    mod.set_fw(self.fw)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            try:
                if "set_int" in dir(mod):
                    mod.set_int(self.interface)
            except Exception, e:
                print e
                if DEBUG:
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
            mod.start_mod()

    def shut_module(self, module, delete=False):
        if DEBUG:
            print "shut %s" % module
        (mod, enabled) = self.modules[module]
        mod.shut_mod()
        for i in self.notebook:
            if self.notebook.get_tab_label_text(i) == mod.name:
                pos = self.notebook.page_num(i)
                self.notebook.remove_page(pos)
                break
        if "get_eth_checks" in dir(mod):
            for i in self.eth_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.eth_checks.remove(i)
        if "get_ip_checks" in dir(mod):
            for i in self.ip_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.ip_checks.remove(i)
        if "get_tcp_checks" in dir(mod):
            for i in self.tcp_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.tcp_checks.remove(i)
        if "get_udp_checks" in dir(mod):
            for i in self.udp_checks:
                (check, call, name) = i
                if name == mod.name:
                    self.udp_checks.remove(i)
        self.modules[module] = (mod, False)
        if delete:
            del self.modules[modules]
        return pos

    def log(self, msg, module=None):
        #if not gtk.Object.flags(self.statusbar) & gtk.IN_DESTRUCTION:
        self.statusbar.push(self.msg_id, "[%i] %s" % (self.msg_id, msg))
        if DEBUG:
            print "[%i] %s" % (self.msg_id, msg)
        self.log_textbuffer.insert(self.log_textbuffer.get_end_iter(), "[%i] %s\n" % (self.msg_id, msg))
        self.msg_id += 1
        if module:
            if module not in self.module_active:
                for i in self.notebook:
                    if self.notebook.get_tab_label_text(i) == module:
                        if self.notebook.page_num(i) == self.notebook.get_current_page():
                            break
                        self.module_active.append(module)
                        self.flash_label(module, self.notebook.get_tab_label(i), 5)
                        break

    def flash_label(self, module, label, times):
        if times > 0:
            if label.get_property("sensitive"):
                label.set_property("sensitive", False)
                gobject.timeout_add(500, self.flash_label, module, label, times)
            else:
                label.set_property("sensitive", True)
                gobject.timeout_add(500, self.flash_label, module, label, times - 1)
        else:
            self.module_active.remove(module)

    def send_msg(self, msg):
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_INFO, gtk.BUTTONS_CLOSE, msg)
        label = gtk.Label(msg)
        dialog.vbox.pack_start(label, True, True, 0)
        dialog.run()
        dialog.destroy()

    ### EVENTS ###

    def on_run_togglebutton_toogled(self, btn):
        if btn.get_active():
            if not self.configured:
                self.on_network_button_clicked(None)
            if not self.configured:
                btn.set_active(False)
                return
            self.pcap_thread = pcap_thread(self, self.interface)
            self.pcap_thread.start()
            self.dnet_thread = dnet_thread(self.interface)
            self.log("Listening on %s" % (self.interface))
            self.fw = dnet.fw()
            for i in self.modules:
                self.start_module(i)
            for i in self.notebook:
                i.set_property("sensitive", True)
            self.network_button.set_property("sensitive", False)
            self.open_togglebutton.set_property("sensitive", False)
            self.dnet_thread.start()
        else:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            for i in self.notebook:
                i.set_property("sensitive", False)
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            if self.dnet_thread:
                self.dnet_thread.quit()
                self.dnet_thread = None
            self.network_button.set_property("sensitive", True)
            self.open_togglebutton.set_property("sensitive", True)

    def on_open_togglebutton_toggled(self, btn):
        if btn.get_active():
            dialog = gtk.FileChooserDialog(title="Open", parent=self.window, action=gtk.FILE_CHOOSER_ACTION_OPEN, buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
            #dialog.set_current_folder()
            filter = gtk.FileFilter()
            filter.set_name("Pcap files")
            filter.add_pattern("*.cap")
            filter.add_pattern("*.pcap")
            dialog.add_filter(filter)
            filter = gtk.FileFilter()
            filter.set_name("All files")
            filter.add_pattern("*")
            dialog.add_filter(filter)
            response = dialog.run()
            if response == gtk.RESPONSE_OK:
                self.pcap_thread = pcap_thread_offline(self, dialog.get_filename())
                if not self.configured:
                    self.interface = "null"
                    self.ip = "0.0.0.0"
                    self.mask = "0.0.0.0"
                for i in self.modules:
                    self.start_module(i)
                for i in self.notebook:
                    i.set_property("sensitive", True)
                self.run_togglebutton.set_property("sensitive", False)
                self.pcap_thread.start()
            else:
                btn.set_active(False)
            dialog.destroy()
        else:
            for i in self.modules:
                (mod, en) = self.modules[i]
                mod.shut_mod()
            for i in self.notebook:
                i.set_property("sensitive", False)
            if self.pcap_thread:
                self.pcap_thread.quit()
                self.pcap_thread = None
            self.run_togglebutton.set_property("sensitive", True)

    def on_pref_button_clicked(self, data):
        pref_window = preference_window(self)
        pref_window.show_all()

    def on_log_button_clicked(self, data):
        l_window = log_window(self.log_textbuffer)
        l_window.show_all()
        
    def on_network_button_clicked(self, data):
        dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Select the interface to use")
        box = gtk.combo_box_new_text()
        devs = pcap.findalldevs()
        for (name, descr, addr, flags) in devs:
            try:
                test = dnet.eth(name)
                test.get()
            except:
                pass
            else:
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
            (module, enabled) = self.modules[i]
            module.shut_mod()
        if self.pcap_thread:
            self.pcap_thread.quit()
        if self.dnet_thread:
            self.dnet_thread.quit()
        return False

    def destroy_event(self, widget, data=None):
        gtk.main_quit()

if __name__ == '__main__':
    if PLATFORM == "Linux" or PLATFORM == "FreeBSD":
        if os.geteuid() != 0:
            print "You must be root to run this script."
            sys.exit(1)
    else:
        print "%s is not supported yet." % (PLATFORM)
        sys.exit(1)
    app = codename_loki()
    signal.signal(signal.SIGINT, app.on_quit_button_clicked)
    try:
        app.main()
    except Exception, e:
        print e
        if DEBUG:
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        app.delete_event(None, None)
    except:
        app.delete_event(None, None)
