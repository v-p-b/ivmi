import zmq
import cmd
import json
"""
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
"""

class IVMIShell(cmd.Cmd):
    intro="Welcome to iVMI!"
    prompt="ivmi# "
    file=None

    def do_connect(self, arg):
        'Connects to the remote iVMI queue specified as argument'
        self.context=zmq.Context()
        self.socket=self.context.socket(zmq.REQ)
        self.socket.connect(arg)
        self.prompt="ivmi[%s]# " % arg
    
    def do_list(self, arg):
        'List running domains'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(b"{\"cmd\":1}")
        print(self.socket.recv())

    def do_init(self, arg):
        'Initialize iVMI. Arguments: <domain> <rekall profile>'
        if not self.socket:
            print ('Not connected!')
            return False
        args=arg.split()
        domain=args[0]
        profile=args[1]
        req={}
        req["cmd"]=2
        req["domain"]=domain
        req["profile"]=json.load(open(profile,"r"))
        self.socket.send(bytes(json.dumps(req),"utf-8"))
        print(self.socket.recv())

    def do_close(self, arg):
        'Close introspection context'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(b"{\"cmd\":240}")
        self.socket.close()


    def do_test(self, arg):
        'Testing'
        print(repr(arg))

if __name__ == '__main__':
    IVMIShell().cmdloop()
    
