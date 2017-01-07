import zmq
import cmd

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

    def do_test(self, arg):
        'Testing'
        print(repr(arg))

if __name__ == '__main__':
    IVMIShell().cmdloop()
    
