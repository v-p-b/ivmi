from base64 import b64decode
from binascii import hexlify
from ivmi import *
import json

DOMAIN="testx64"
PROFILE="/home/b/testx64.rekall.json"

ivmi=IVMI()

ivmi.connect("tcp://127.0.0.1:22000","tcp://127.0.0.1:22001")

info=ivmi.init(DOMAIN,PROFILE)
print(repr(info))

trap=IVMITrap()

trap.name="KiDispatchException"
trap.module="ntoskrnl.exe"
trap.pid=4
trap.addr_type="RVA"
trap.lookup_type="PID"
trap.addr=ivmi.profile["$FUNCTIONS"]["KiDispatchException"] 

print(repr(ivmi.add_trap(trap)))
ivmi.resume()
for i in range(0,3):
    n=ivmi.get_notification(blocking=True)
    print(repr(n))
    #info=ivmi.info()
    #print(repr(info))
   
    """ 
    if info['page_mode']=="IA32E":
        #trap_frame=b64decode(ivmi.read_mem(4, n["regs"]["r8"], ivmi.profile["$STRUCTS"]["_KTRAP_FRAME"][0]))
        #print(hexlify(trap_frame))
        print(hexlify(b64decode(ivmi.read_mem(4,n["regs"]["rcx"],4))))
    """
    ivmi.ack_notification()
    
print(repr(ivmi.del_trap("KiDispatchException")))
ivmi.close()

