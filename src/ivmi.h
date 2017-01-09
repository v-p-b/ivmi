#ifndef VEBUG_H
#define VEBUG_H

#include <libdrakvuf/libdrakvuf.h>
#include <unistd.h>
#include <glib.h>

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
    CMD_CLOSE = 0xf0,
    CMD_BYE = 0xff
};

typedef struct ivmi {
    drakvuf_t drakvuf;
    GThread* drakvuf_loop;
    uint64_t domid;
    struct{
        uint64_t pid;
        uint64_t cr3;
    } process;
} ivmi_t;

#endif
