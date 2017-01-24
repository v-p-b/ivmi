from ivmi import *
import json

DOMAIN="testx64"
PROFILE="/home/b/testx64.rekall.json"

ivmi=IVMI()

ivmi.connect("tcp://127.0.0.1:22000","tcp://127.0.0.1:22001")

print(repr(ivmi.init(DOMAIN,PROFILE)))

trap=IVMITrap()

trap.name="KiDispatchException"
trap.module="ntoskrnl.exe"
trap.pid=4
trap.addr_type="RVA"
trap.lookup_type="PID"
trap.addr=ivmi.profile["$FUNCTIONS"]["KiDispatchException"] 

#if trap.addr != 774598:
#    ivmi.close()
#    exit()

print(repr(ivmi.add_trap(trap)))
ivmi.resume()
for i in range(0,30):
    n=ivmi.get_notification(blocking=True)
    print(repr(n))
    ivmi.ack_notification()
    
print(repr(ivmi.del_trap("KiDispatchException")))
ivmi.close()

