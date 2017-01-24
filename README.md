iVMI
====

Interactive Virtual Machine Introspection based on [DRAKVUF](https://drakvuf.com) and [libvmi](https://libvmi.com). The aim of this project is to create a language independent wrapper to facilitate VMI-based tool prototyping, scripting and debugging. 

Building
--------

* Install [DRAKVUF](https://drakvuf.com).
* Install ZMQ. On Ubuntu Trusty it's `apt-get install libzmq3 libzmq3-dev`
* Install zmqpp (the C++ interface for ZMQ): On Ubuntu Trusty it's `apt-get install libzmqpp3 libzmqpp-dev`
* Install CMake: On Ubuntu Trusty it's `apt-get install cmake`
* Install pyzmq for Python3 ZMQ support: `pip install pyzmq`

Clone the repository and enter your local directory, then initialize submodules:

```
git submodule init
git submodule update
cd drakvuf
git submodule init
git submodule update
```

Build:

```
cd .. # Now we're back in the root of our copy of ivmi 
mkdir build
cd build
cmake ..
make
```

If the build succeeds you can start ivmi: `src/ivmi`

Interface
---------

iVMI provides two basic facilities around the lower level VMI components:
* Communication over [ZeroMQ](http://zeromq.org): This provides a transport-independent communication channel. You can connect locally using Unix domain sockets or over the network via TCP.
* JSON serialization: Every message passed over ZMQ is in JSON format, that is highly portable and human readable. 

iVMI reserves two channels for communication:
* A Control channel is used for sending commands to iVMI and receive the results. This is a classic client-server architecture implemented as a ZMQ REQ-REP socket pair. 
* A Notification channel is used for asynchronous delivery of VMI events (breakpoint traps for now). This is a ZMQ PUSH-PULL socket pair.

Example clients in Python 3 are provided, it is recommended to use these as reference.

### List domains (VMs)

Currently this returns the output of `xl list`

Example request:

```js
{"cmd": CMD_LIST}
```

### Initialize for domain

This is how you assign your session to a given VM. You have to provide the name of the domain and a JSON formatted Rekall profile that describes the expected memory layout

Example request:

```js
{"cmd": CMD_INIT, "domain", "testdomain", "profile": rekall_profile_obj }
```

The response contains basic information about the domain and the iVMI context (same as Info).

### Info

General information about the current state of the domain and the iVMI context.

Example request:

```js
{"cmd": CMD_LIST}
```

### (Un)Pause domain

Pause or resume execution of the introspected domain.

Example requests:

```js
{"cmd": CMD_PAUSE}
```

```js
{"cmd": CMD_RESUME}
```

### Process list

*Windows only*

Lists running processes. This is equivalent to libvmi's `process-list` working with Windows and Linux (Linux not tested).

Example request:

```js
{"cmd": CMD_PROC_LIST}
```

### Process module list

*Windows only*

List process modules and their relative addresses.

Example request:

```js
{"cmd": CMD_PROC_MOUDLES, "pid": 1234}
```

### Memory read/write

You can access the raw memory of the VM. 

In case of PID=0 the address is treated as *physical*, otherwise it's treated as virtual (for the given process).   

Example requests:

```js
{"cmd": CMD_MEM_READ, "pid":1234, "addr": 0xdeadbeef, "len": 32}
```

```js
{"cmd": CMD_MEM_WRITE, "pid": 1234, "addr": 0xdeadbeef, "contents": "QUFBQQ=="}
```

Memory contents are serialized to Base64.

### Get/Set Registers

The title says it all. 

Example requests:

```js
{"cmd": CMD_REG_READ, "reg": "EAX", "vcpuid": 0}
```

```js
{"cmd": CMD_REG_WRITE, "reg": "RAX", "vcpuid": 0, "value": 1}
```

### Add trap

Currently you can set breakpoints and handle them in your client. 

Trap object example:

```js
{"name": "UniqueName", "addr_type": "VA", "lookup_type": "PID", "addr": 0xdeadbeef, "pid": 4}
```

For possible combinations of lookup types and addressing please see the source!

Example trap addition:

```js
{"cmd": CMD_TRAP_ADD, "trap": trap_obj}
```

Breakpoint events are delivered through the notification channel.

### Notification acknowlegdement

When a breakpoint is hit a callback is executed in iVMI that pushes a JSON object with information about the event down the Notification channel. The execution of the affected VCPU is stopped until this callback returns. You can make the callback return by sending a Notification Acknowledgement on the Control channel.

```js
{"cmd": CMD_NOTIFY_CONT, "trap": trap_obj}
```

### Remove trap

You can remove traps by name (it's important to register traps with unique names).

```js
{"cmd": CMD_TRAP_DEL, "trap_name": "UniqueName"}
```

### Closing context

Detach from the introspected domain, remove all traps. Pending notifications are discarded. You should always close your contexts otherwise your VMs will break. 

```js
{"cmd": CMD_CLOSE}
```

OS support
----------

As libvmi allows access to raw guest memory and registers it is posibble to implement any OS dependent functionality at client side. In practice, DRAKVUF supports 32 and 64-bit Windows 7 and Linux. High level utility functions in iVMI were tested with Windows guests. 

At server side Linux on Xen is supported.

Known issues
------------

This is an early release, so: 

* Your VMs and even your hypervisor may crash (ProTip: don't mess with physical addresses if you're not sure what you're doing) 
* APIs are subject to change
* No full guest multi-CPU support
* Handling non-Windows/OS independent API calls is under way
* CMake build scripts likely suck, this is my first time...

If you find a bug, use the Issue Tracker.
