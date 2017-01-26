import cmd
import ivmi
import _thread

class IVMIShell(cmd.Cmd):
    intro="Welcome to iVMI!"
    prompt="ivmi# "
    domain=None
    control=None
    notify=None
    ns=[]
    ivmi=ivmi.IVMI()

    def update_prompt(self):
        parts=[]
        if self.control != None:
            parts.append("[%s]" % self.control)
        if self.domain != None:
            parts.append("[%s]" % self.domain)
        self.prompt="ivmi%s# " % (''.join(parts))

    def notify_loop(self):
        while True:
            n=self.ivmi.get_notification(blocking=True,ack=True)
            self.ns.append(n)

    def do_connect(self, arg):
        'Connects to the remote iVMI queue specified as argument'
        args=arg.split()
        self.ivmi.connect(args[0],args[1])
        _thread.start_new_thread(self.notify_loop,tuple())
        self.control=args[0]
        self.notify=args[1]
        self.update_prompt()
    
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
        self.domain=domain
        self.update_prompt()
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

    def do_add_trap(self, arg):
        'Add trap based on PID & module: add_trap <name> <PID> <module> <virtual address>'
        trap=ivmi.IVMITrap()
        args=arg.split()

        trap.lookup_type="PID"
        trap.addr_type="RVA"
        trap.name=str(args[0])
        trap.pid=int(args[1])
        trap.module=str(args[2])
        trap.addr=int(args[3]) 
        
        res=self.ivmi.add_trap(trap)
        print(repr(res))

    def do_get_notifications(self, arg):
        'Get received notifications'
        nnum=0
        while len(self.ns)>0:
            print(repr(self.ns.pop()))
            nnum+=1
        print("Returned %d notifications." % nnum)
            
    def do_close(self, arg):
        'Close introspection context'
        self.ivmi.close()
        self.control=None
        self.notify=None
        self.domain=None
        self.update_prompt()

    def do_pause(self, arg):
        'Pause VM'
        res=self.ivmi.pause()
        print(repr(res))

    def do_resume(self, arg):
        'Resume VM'
        res=self.ivmi.resume()
        print(repr(res))

    def do_exit(self, arg):
        'Exit'
        if self.control != None:
            self.do_close(None)
        return True

if __name__ == '__main__':
    IVMIShell().cmdloop()
    
