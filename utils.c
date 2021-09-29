/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#define KFUN(module, offset) (void *)module_get_offset(0x10005, searchModule(module), 0, offset)

void* module_get_offset(unsigned int pid, unsigned int modid, int segidx, size_t offset) {
    SceKernelModuleInfo sceinfo;
    if (segidx > 3)
        return 0;
    sceinfo.size = sizeof(sceinfo);
    if (getModule == NULL)
        return 0;
    if (getModule(pid, modid, &sceinfo) < 0)
        return 0;
    if (offset > sceinfo.segments[segidx].memsz)
        return 0;
    return (void*)sceinfo.segments[segidx].vaddr + offset;
}

static inline unsigned int xsmc(unsigned int arg1, unsigned int arg2, unsigned int arg3, unsigned int arg4, unsigned int cmd) {
    register unsigned int r0 asm("r0") = arg1;
    register unsigned int r1 asm("r1") = arg2;
    register unsigned int r2 asm("r2") = arg3;
    register unsigned int r3 asm("r3") = arg4;
    register unsigned int r12 asm("r12") = cmd;

    asm volatile(
        "smc #0\n\t"
        : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
        : "r"(r12)
        );

    return r0;
}

static int hex_dump(const char* addr, unsigned int size, uint32_t start_off, k_root* kroot) {
    unsigned int i;
    for (i = 0; i < (size >> 4); i++) {
        kroot->printf("0x%08X: |%02X%02X%02X%02X%02X%02X%02X%02X|%02X%02X%02X%02X%02X%02X%02X%02X|\n", start_off + (i * 0x10), addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        addr += 0x10;
    }
    return 0;
}

// i/o fix when system is running
int siofix(void* func) {
    int (*create_thread)(const char* name, void* func, int a2, int a3, int a4, int a5, int a6) = KFUN("SceKernelThreadMgr", 0x7d10 | 1);
    int (*start_thread)(int id, int argsz, void* argv) = KFUN("SceKernelThreadMgr", 0x3514 | 1);
    int (*wait_thread)(int id, int* ret, void* argv) = KFUN("SceKernelThreadMgr", 0x3008 | 1);
    int (*delete_thread)(int id) = KFUN("SceKernelThreadMgr", 0x3394 | 1);
    int ret, res, uid;
    ret = uid = create_thread("siofix", func, 0x10000100, 0x4000, 0, 0x10000, 0);
    if (ret < 0) { ret = -1; goto cleanup; }
    if ((ret = start_thread(uid, 0, NULL)) < 0) { ret = -1; goto cleanup; }
    if ((ret = wait_thread(uid, &res, NULL)) < 0) { ret = -1; goto cleanup; }
    ret = res;
cleanup:
    if (uid > 0) delete_thread(uid);
    return ret;
}

int read_file(void* dst, const char* src, uint32_t size, k_root* kroot) {
    if (!kroot)
        return -1;
    kroot->printf("[SNS][RF] read_file(%s, 0x%X)\n", src, size);
    int (*iof_open)(const char* file, int mode, int flags) = KFUN("SceIofilemgr", 0x708 | 1);
    int (*iof_read)(int fd, void* dst, uint32_t sz) = KFUN("SceIofilemgr", 0x784 | 1);
    int (*iof_close)(int fd) = KFUN("SceIofilemgr", 0x67c | 1);
    if (!iof_open || !dst || !src || !size)
        return -2;
    int fd = iof_open(src, 1, 1);
    if (fd < 0)
        return -3;
    iof_read(fd, dst, size);
    iof_close(fd);
    return 0;
}

int write_file(const char* dst, void* src, uint32_t size, int mode, k_root* kroot) {
    if (!kroot || !dst || !src || !size)
        return -1;
    kroot->printf("[SNS][WF] write_file(%s, 0x%X)\n", dst, size);
    int (*iof_open)(const char* file, int mode, int flags) = KFUN("SceIofilemgr", 0x708 | 1);
    int (*iof_write)(int fd, void* src, uint32_t sz) = KFUN("SceIofilemgr", 0x804 | 1);
    int (*iof_close)(int fd) = KFUN("SceIofilemgr", 0x67c | 1);
    if (!src || !iof_open)
        return -2;
    if (!mode)
        mode = 2 | 0x200 | 0x400;
    int fd = iof_open(dst, mode, 6);
    if (fd < 0)
        return -3;
    iof_write(fd, src, size);
    iof_close(fd);
    return 0;
}