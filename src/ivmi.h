#ifndef VEBUG_H
#define VEBUG_H

#include <libdrakvuf/libdrakvuf.h>
#include <unistd.h>
#include <glib.h>
#include <zmqpp/zmqpp.hpp>
#include <libvmi/libvmi.h>
#include <unordered_map>
#include <string>

enum VEBUG_CMD
{
    CMD_LIST = 0x1,
    CMD_INIT = 0x2,
    CMD_PAUSE = 0x3,
    CMD_RESUME = 0x4,
    CMD_MEM_R = 0x5,
    CMD_MEM_W = 0x6,
    CMD_REG_R = 0x7,
    CMD_REG_W = 0x8,
    CMD_TRAP_ADD = 0x9,
    CMD_TRAP_DEL = 0xA,
    CMD_INFO = 0x10,
    CMD_PROC_LIST = 0x11,
    CMD_FIND_PROC = 0x12,
    CMD_PROC_MODULES = 0x13,
    CMD_NOTIFY_CONT = 0x80,
    CMD_CLOSE = 0xf0,
    CMD_BYE = 0xff
};

typedef struct ivmi {
    drakvuf_t drakvuf;
    GThread* drakvuf_loop;
    char* domain;
    bool paused;
    bool closing;
    os_t os;
    page_mode_t pm; 
    zmqpp::socket* notify;
    gint notify_lock;
    std::unordered_map<std::string, drakvuf_trap_t*> traps;
} ivmi_t;

std::unordered_map<std::string, reg_t> ivmi_regs={
    {"EAX",EAX},
    {"EBX",EBX},
    {"ECX",ECX},
    {"EDX",EDX},
    {"EBP",EBP},
    {"ESI",ESI},
    {"EDI",EDI},
    {"ESP",ESP},

    {"EIP",EIP},
    {"EFLAGS",EFLAGS},

    {"RAX",RAX},
    {"RBX",RBX},
    {"RCX",RCX},
    {"RDX",RDX},
    {"RBP",RBP},
    {"RSI",RSI},
    {"RDI",RDI},
    {"RSP",RSP},

    {"RIP",RIP},
    {"RFLAGS",RFLAGS},

    {"R8",R8},
    {"R9",R9},
    {"R10",R10},
    {"R11",R11},
    {"R12",R12},
    {"R13",R13},
    {"R14",R14},
    {"R15",R15},

    {"CR0",CR0},
    {"CR2",CR2},
    {"CR3",CR3},
    {"CR4",CR4},
    {"XCR0",XCR0},

    {"DR0",DR0},
    {"DR1",DR1},
    {"DR2",DR2},
    {"DR3",DR3},
    {"DR6",DR6},
    {"DR7",DR7},

    {"CS_SEL",CS_SEL},
    {"DS_SEL",DS_SEL},
    {"ES_SEL",ES_SEL},
    {"FS_SEL",FS_SEL},
    {"GS_SEL",GS_SEL},
    {"SS_SEL",SS_SEL},
    {"TR_SEL",TR_SEL},
    {"LDTR_SEL",LDTR_SEL},

    {"CS_LIMIT",CS_LIMIT},
    {"DS_LIMIT",DS_LIMIT},
    {"ES_LIMIT",ES_LIMIT},
    {"FS_LIMIT",FS_LIMIT},
    {"GS_LIMIT",GS_LIMIT},
    {"SS_LIMIT",SS_LIMIT},
    {"TR_LIMIT",TR_LIMIT},
    {"LDTR_LIMIT",LDTR_LIMIT},
    {"IDTR_LIMIT",IDTR_LIMIT},
    {"GDTR_LIMIT",GDTR_LIMIT},

    {"CS_BASE",CS_BASE},
    {"DS_BASE",DS_BASE},
    {"ES_BASE",ES_BASE},
    {"FS_BASE",FS_BASE},
    {"GS_BASE",GS_BASE},
    {"SS_BASE",SS_BASE},
    {"TR_BASE",TR_BASE},
    {"LDTR_BASE",LDTR_BASE},
    {"IDTR_BASE",IDTR_BASE},
    {"GDTR_BASE",GDTR_BASE},

    {"CS_ARBYTES",CS_ARBYTES},
    {"DS_ARBYTES",DS_ARBYTES},
    {"ES_ARBYTES",ES_ARBYTES},
    {"FS_ARBYTES",FS_ARBYTES},
    {"GS_ARBYTES",GS_ARBYTES},
    {"SS_ARBYTES",SS_ARBYTES},
    {"TR_ARBYTES",TR_ARBYTES},
    {"LDTR_ARBYTES",LDTR_ARBYTES},

    {"SYSENTER_CS",SYSENTER_CS},
    {"SYSENTER_ESP",SYSENTER_ESP},
    {"SYSENTER_EIP",SYSENTER_EIP}
};

#endif
