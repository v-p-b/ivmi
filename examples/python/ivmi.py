import zmq
import json

class IVMITrap():
    name=""
    addr_type="PA"
    lookup_type="NONE"
    pid=0
    module=""
    proc=""
    addr=0

class IVMITrapEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, IVMITrap):
            if obj.lookup_type not in ("NONE","PID","DTB","NAME"):
                raise Exception("Invalid Lookup type %s" % obj.lookup_type)
            if obj.addr_type not in ("PA","VA","RVA"):
                raise Exception("Invalid Address type %s" % obj.addr_type)
            ret={}
            ret["name"]=str(obj.name)
            ret["lookup_type"]=obj.lookup_type
            ret["addr_type"]=obj.addr_type
            ret["pid"]=int(obj.pid)
            ret["module"]=str(obj.module)
            ret["proc"]=str(obj.proc)
            ret["addr"]=int(obj.addr)
            return ret
        return json.JSONEncoder.default(self, obj)

class IVMI():
    CMD_LIST = 0x1
    CMD_INIT = 0x2
    CMD_PAUSE = 0x3
    CMD_RESUME = 0x4
    CMD_MEM_R = 0x5
    CMD_MEM_W = 0x6
    CMD_REG_R = 0x7
    CMD_REG_W = 0x8
    CMD_TRAP_ADD = 0x9
    CMD_TRAP_DEL = 0xA
    CMD_INFO = 0x10
    CMD_PROC_LIST = 0x11
    CMD_FIND_PROC = 0x12
    CMD_PROC_MODULES = 0x13
    CMD_NOTIFY_CONT = 0x80
    CMD_CLOSE = 0xf0
    CMD_BYE = 0xff

    def __init__(self):
        _traps = {}

    def connect(self, url, notify_url):
        'Connects to the remote iVMI queue specified as argument'
        self.context=zmq.Context()
        self.socket=self.context.socket(zmq.REQ)
        self.socket.connect(url)
        self.notify=self.context.socket(zmq.PULL)
        self.notify.connect(notify_url)
        return (self.context, self.socket)

    def ack_notification(self):
        if not self.notify:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_NOTIFY_CONT}),"utf-8")) 
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def get_notification(self, ack=False, blocking=False):
        if not self.notify:
            print ('Not connected!')
            return False
        flags=0
        if not blocking:
            flags=zmq.NOBLOCK
        try:
            ret=json.loads(self.notify.recv(flags).decode('utf-8', errors='replace'))
            if ack: 
                self.ack_notification()
            return ret
        except zmq.error.Again:
            return None

    def list(self):
        'List running domains'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_LIST}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def init(self, domain, profile):
        'Initialize iVMI. Arguments: <domain> <rekall profile>'
        if not self.socket:
            print ('Not connected!')
            return False
        req={}
        req["cmd"]=self.CMD_INIT
        req["domain"]=domain
        self.profile=json.load(open(profile,"r"))
        req["profile"]=self.profile
        self.socket.send(bytes(json.dumps(req),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def info(self):
        'Information about the current context'
        if not self.socket:
            print ('Not connected!')
            return False
        req={}
        req["cmd"]=self.CMD_INFO
        self.socket.send(bytes(json.dumps(req),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def ps(self):
        'Process list'
        if not self.socket:
            print ('Not connected!')
            return False
        req={}
        req["cmd"]=self.CMD_PROC_LIST
        self.socket.send(bytes(json.dumps(req),"utf-8"))
        ret=self.socket.recv()
        return json.loads(ret.decode('utf-8',errors='replace'))

    def find_pid(self, pid):
        'Find EPROCESS address based on PID'
        if not self.socket:
            print ('Not connected!')
            return False        
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_FIND_PROC, "pid": pid}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def proc_modules(self, pid):
        'Find process modules based on PID'
        if not self.socket:
            print ('Not connected!')
            return False        
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_PROC_MODULES, "pid": pid}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def close(self):
        'Close introspection context'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_CLOSE}),"utf-8"))
        ret=json.loads(self.socket.recv().decode('utf-8',errors='replace'))
        self.socket.close()
        return ret

    def read_mem(self, pid, addr, length):
        'Read memory from virtual or physical address'
        if not self.socket:
            print ('Not connected!')
            return False        
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_MEM_R, "pid": pid, "addr": addr, "len": length}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))
       
    def write_mem(self, pid, addr, contents):
        'Write memory to virtual or physical address'
        if not self.socket:
            print ('Not connected!')
            return False        
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_MEM_W, "pid": pid, "addr": addr, "contents": contents}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))
    
    def get_reg(self, reg, vcpuid=0):
        'Get register value'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_REG_R, "reg": str(reg), "vcpuid": vcpuid}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def set_reg(self, reg, value, vcpuid=0):
        'Set register value'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd": self.CMD_REG_W, "reg": str(reg), "value": int(value), "vcpuid": vcpuid}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def pause(self):
        'Pause VM'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_PAUSE}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def resume(self):
        'Resume VM'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_RESUME}),"utf-8"))
        return json.loads(self.socket.recv().decode('utf-8',errors='replace'))

    def add_trap(self, trap):
        'Add Trap'
        if not self.socket:
            print ('Not connected!')
            return False
        trap_encoded=IVMITrapEncoder().default(trap)
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_TRAP_ADD, "trap":trap_encoded}),"utf-8"))
        ret = json.loads(self.socket.recv().decode('utf-8',errors='replace'))
        return ret

    def del_trap(self, trap_name):
        'Remove trap (by trap name)'
        if not self.socket:
            print ('Not connected!')
            return False
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_TRAP_DEL, "trap_name":trap_name}),"utf-8"))
        ret = json.loads(self.socket.recv().decode('utf-8',errors='replace'))
        return ret

       
 
