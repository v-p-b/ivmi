import zmq
import json

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
    CMD_CLOSE = 0xf0
    CMD_BYE = 0xff

    def connect(self, url):
        'Connects to the remote iVMI queue specified as argument'
        self.context=zmq.Context()
        self.socket=self.context.socket(zmq.REQ)
        self.socket.connect(url)
        return (self.context, self.socket)

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
        self.socket.send(bytes(json.dumps({"cmd":self.CMD_FIND_PROC,"pid":pid}),"utf-8"))
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

