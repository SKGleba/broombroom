/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <inttypes.h>
#include <stdio.h>
#include "standalone.h"
//#include "cmep-payloads/bobloader/bobloader.h" // cmep payload that loads bob to private mem and jumps to it
//#include "bob.bin.h" // BOB

static k_root g_kroot;

static int (*searchModule)(const char* name) = (void*)(0x390000 + 0x275c + 1);
static int (*getModule)(int pid, int uid, SceKernelModuleInfo* info) = (void*)(0x390000 + 0x2854 + 1);

#include "utils.c" // misc
#include "cmep.c" // cmep-related code
#include "tz.c" // tz exec code

// alloc memblocks and get memcpy/memset
int k_init(k_root* kroot) {
    void (*memset)(void* dst, int ch, int sz) = KFUN("SceSysmem", 0x2ca4);
    if (!kroot || !memset)
        return -1;
    memset(kroot, 0, sizeof(k_root));
    kroot->memset = memset;
    kroot->memcpy = KFUN("SceSysmem", 0xf80);
    kroot->printf = KFUN("SceSysmem", 0x2b58c | 1);
    if (!kroot->memcpy || !kroot->printf)
        return -2;

    kroot->printf("[SNS][INIT] k_init started, allocing memblocks\n");

    int (*alloc_mb)(const char* name, int type, int size, alloc_mb_opt * opt) = KFUN("SceSysmem", 0x8a40 | 1);
    int (*get_mb)(int uid, void* out_va) = KFUN("SceSysmem", 0x1a1a4 | 1);

    alloc_mb_opt mbopt;
    memset(&mbopt, 0, sizeof(alloc_mb_opt));
    mbopt.size = sizeof(alloc_mb_opt);
    mbopt.attr = 2;
    mbopt.paddr = 0x1f850000; // v128K scratchpad - seen by vnz and mep, bottom half
    kroot->venezia_spram_mb = alloc_mb("SPAD128K-mep", 0x10208006, 0x10000, &mbopt);
    get_mb(kroot->venezia_spram_mb, &kroot->venezia_spram);

    memset(&mbopt, 0, sizeof(alloc_mb_opt));
    mbopt.size = sizeof(alloc_mb_opt);
    mbopt.attr = 2;
    mbopt.paddr = 0x1c000000; // tachyon eDRAM
    kroot->tachyon_edram_mb = alloc_mb("Tachyon-eDRAM", 0x10208006, 0x200000, &mbopt);
    get_mb(kroot->tachyon_edram_mb, &kroot->tachyon_edram);

    memset(&mbopt, 0, sizeof(alloc_mb_opt));
    mbopt.size = sizeof(alloc_mb_opt);
    mbopt.attr = 2;
    mbopt.paddr = 0x4c000000; // some arm DRAM
    kroot->pac_dram_mb = alloc_mb("ARM-pacDRAM", 0x10208006, 0x20000, &mbopt);
    get_mb(kroot->pac_dram_mb, &kroot->pac_dram);

    if (!kroot->venezia_spram || !kroot->tachyon_edram || !kroot->pac_dram) {
        kroot->printf("[SNS][INIT] mballoc failed %d %d %d\n", !kroot->venezia_spram, !kroot->tachyon_edram, !kroot->pac_dram);
        return -3;
    }

    int (*umemcpy)() = KFUN("SceSysmem", 0x25c1c | 1);
    umemcpy(&g_kroot, kroot, sizeof(k_root));
    return 0;
}

// free memblocks and cleanup
void k_uinit(k_root* kroot) {
    if (!kroot)
        return;
    if (kroot->printf)
        kroot->printf("[SNS][UINIT] k_uinit called, cleaning up\n");
    int (*free_mb)(int uid) = KFUN("SceSysmem", 0x9840 | 1);
    if (!free_mb)
        return;
    free_mb(kroot->venezia_spram_mb);
    free_mb(kroot->tachyon_edram_mb);
    free_mb(kroot->pac_dram_mb);
    if (kroot->printf)
        kroot->printf("[SNS][UINIT] memblocks freed, destroying self, bye!\n");
    if (kroot->memset)
        kroot->memset(kroot, 0, sizeof(k_root));
    return;
}

// main code
int gp_main(void* usl) {
    k_root kroot;
    int ret = k_init(&kroot);
    if (ret)
        return ret;

    kroot.printf("[SNS] hello world from standalone\n");

    // copy our custom reset func and cry2arm0 handler
    ret = tz_init(&kroot);
    kroot.printf("[SNS] tz_init ret 0x%X\n", ret);
    if (ret)
        goto kexit;

    // install a tiny code exec framework in cmep secure_kernel
    ret = siofix(cmep_init);
    kroot.printf("[SNS] cmep_init ret 0x%X\n", ret);
    if (ret)
        goto kexit;

    brom_init(&kroot);

    int reset = 8;
reset_fud:
    // reset cmep with our fake secure_kernel
    ret = tz_load_fake_sk(&kroot, 0x4C000000, reset);
    kroot.printf("[SNS] fudreset ret 0x%X\n", ret);
    if (ret < 0)
        goto kexit;

    // ----------start bootrom memes here

    bromcpy(0x1c100000, 0x00040000, 0x00020000, &kroot);
    hex_dump(kroot.tachyon_edram + 0x100000, 0x00020000, 0x00040000, &kroot);

    // reset cmep and run the code again
    if (!reset) {
        reset = 8;
        goto reset_fud;
    }

    // ----------stop bootrom memes there

    kroot.printf("[SNS] finished without errors, exiting\n");
kexit:
    k_uinit(&kroot);
    return 0;
}

// payload start, jump to main
__attribute__((section(".text.start"))) int start(void* sl) {
    int ret = gp_main(sl);
    return ret;
}