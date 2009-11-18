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

import gobject
import gtk
gtk.gdk.threads_init()

VERSION = "v0.1"

class loki(object):
    def __init__(self):
        self.modules = {}
        self.msg_id = 0
        
        #gtk stuff
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)

        self.window.set_title(self.__class__.__name__)
        self.window.set_default_size(640, 480)

        #connect signal handlers
        self.window.connect("delete_event", self.delete_event)
        self.window.connect("destroy", self.destroy_event)

        self.vbox = gtk.VBox(False, 0)
        self.notebook = gtk.Notebook()
        self.vbox.pack_start(self.notebook, True, True, 0)
        self.statusbar = gtk.Statusbar()
        self.vbox.pack_start(self.statusbar, False, False, 0)
        self.window.add(self.vbox)

    def main(self):
        self.load_modules()
        self.init_modules()

        self.window.show_all()
        
        gtk.main()

    def load_modules(self, path="./modules/"):
        #import the modules
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                (name, ext) = os.path.splitext(i)
                if ext == ".py":
                    try:
                        module = __import__(name)
                        print module
                        self.modules[name] = module.mod_class(self)
                        print "Imported module " + name
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
            self.modules[i].thread.start()

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
    def delete_event(self, widget, event, data=None):
        for i in self.modules.keys():
            self.modules[i].shutdown()
        return False

    def destroy_event(self, widget, data=None):
        gtk.main_quit()

if __name__ == '__main__':
    app = loki()
    app.main()
