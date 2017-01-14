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

    def do_modules(self, arg):
        'List process modules based on EPROCESS and PID'
        res=self.ivmi.proc_modules(int(arg))
        print(repr(res))

    def do_read_mem(self, arg):
        'Read memory  <pid (0 if physical)> <address> <length>'
        args=arg.split()
        res=self.ivmi.read_mem(int(args[0]),int(args[1]),int(args[2]))
        print(repr(res))

    def do_write_mem(self, arg):
        'Write memory  <pid (0 if physical)> <address> <contents base64>'
        args=arg.split()
        res=self.ivmi.write_mem(int(args[0]),int(args[1]),args[2])
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
    
