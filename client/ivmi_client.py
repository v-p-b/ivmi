import cmd
import ivmi

class IVMIShell(cmd.Cmd):
    intro="Welcome to iVMI!"
    prompt="ivmi# "
    ivmi=ivmi.IVMI()

    def do_connect(self, arg):
        'Connects to the remote iVMI queue specified as argument'
        self.ivmi.connect(arg)
        self.prompt="ivmi[%s]# " % arg
    
    def do_list(self, arg):
        'List running domains'
        res=self.ivmi.list()
        print(repr(res))

    def do_init(self, arg):
        'Initialize iVMI. Arguments: <domain> <rekall profile>'
        args=arg.split()
        domain=args[0]
        profile=args[1]
        res=self.ivmi.init(domain,profile)
        print(repr(res))

    def do_info(self, arg):
        'Information about the current context'
        res=self.ivmi.info()
        print(repr(res))

    def do_ps(self, arg):
        'Process list'
        res=self.ivmi.ps()
        print(repr(res))
    
    def do_pid(self, arg):
        'Find EPROCESS address based on PID'
        res=self.ivmi.find_pid(int(arg))
        print(repr(res))

    def do_close(self, arg):
        'Close introspection context'
        self.ivmi.close()
        self.prompt="ivmi# "

    def do_pause(self, arg):
        'Pause VM'
        res=self.ivmi.pause()
        print(repr(res))

    def do_resume(self, arg):
        'Resume VM'
        res=self.ivmi.resume()
        print(repr(res))

if __name__ == '__main__':
    IVMIShell().cmdloop()
    
