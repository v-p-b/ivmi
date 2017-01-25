from base64 import b64decode
from binascii import hexlify
from ivmi import *
from struct import unpack
import argparse
import json

ap=argparse.ArgumentParser()
ap.add_argument("-d","--domain", help="Domain to attach to")
ap.add_argument("-p","--profile", help="Rekall profile to use")
ap.add_argument("-c","--control", help="iVMI Control socket", default="tcp://127.0.0.1:22000")
ap.add_argument("-n","--notify", help="iVMI Nofitication socket", default="tcp://127.0.0.1:22001")
ap.add_argument("-i","--iter", help="Interations - Number of exceptions to intercept before closing connection", type=int, default=5)
args = ap.parse_args()

ivmi=IVMI()

ivmi.connect(args.control, args.notify)

info=ivmi.init(args.domain, args.profile)

ktrap_size = ivmi.profile["$STRUCTS"]["_KTRAP_FRAME"][0]
ktrap_regs = {}
for r in ["Rax","Rbx","Rcx","Rdi","Rsi","Rbp","Rip","Rsp"]:
    ktrap_regs[r] = ivmi.profile["$STRUCTS"]["_KTRAP_FRAME"][1][r][0]

print(repr(info))

trap=IVMITrap()

trap.name="KiDispatchException"
trap.module="ntoskrnl.exe"
trap.pid=4
trap.addr_type="RVA"
trap.lookup_type="PID"
trap.addr=ivmi.profile["$FUNCTIONS"]["KiDispatchException"] 

ivmi.add_trap(trap)
ivmi.resume()

print("Initialized...")

try:
    for i in range(0,args.iter):
        n=ivmi.get_notification(blocking=True)
        print(repr(n))
        #info=ivmi.info()
        #print(repr(info)) 
        if info['page_mode']=="IA32E":
            exception_code=unpack("I",b64decode(ivmi.read_mem(4,n["regs"]["rcx"],4)))[0]
            print("EXCEPTION CODE: %x" % exception_code)
            trap_frame=b64decode(ivmi.read_mem(4, n["regs"]["r8"],ktrap_size))
            for r, v in ktrap_regs.items():
                print("%s: %lx" % (r,unpack("Q",trap_frame[v:v+8])[0]))
            pass
        ivmi.ack_notification()
finally:    
    ivmi.close()

