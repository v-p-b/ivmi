#ifndef VEBUG_H
#define VEBUG_H
#define _GNU_SOURCE

enum VEBUG_CMD
{
    CMD_INIT = 0x1;
    CMD_PAUSE = 0x2;
    CMD_RESUME = 0x3;
    CMD_MEM_R = 0x4;
    CMD_MEM_W = 0x5;
    CMD_REG_R = 0x6;
    CMD_REG_W = 0x7;
    CMD_TRAP_ADD = 0x8;
    CMD_TRAP_DEL = 0x9;
}

#endif
