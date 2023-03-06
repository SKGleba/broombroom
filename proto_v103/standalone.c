/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <inttypes.h>
#include <stdio.h>
#include "standalone.h"
#include "cmep-payloads/enable_reset/enable_reset.h" // cmep payload to enable f00d reset with paddr from arm
#include "cmep-payloads/brom_crash_print/brom_crash_print.h" // custom exception handler for bootrom with fakesl
#include "cmep-payloads/brom_ccode/fakesl_ccode.h" // custom bootrom test code

/*
        000400b0 21 c1 04 00     movh       r1,0x4
        000400b4 10 c1 c0 00     add3       r1,r1,#0xc0
        000400b8 d9 de 8c 00     bsr        SUB_00048d92
        000400bc 15 b0           bsr        SUB_000400d0
        000400be f2 bf           bra        LAB_000400b0
        000400c0 5b 42 52        ds         "[BROM] crashed\n"
                 4f 4d 5d
                 20 63 72
*/
static const unsigned char fakesl_evh[] = {
    0x21, 0xc1, 0x04, 0x00, 0x10, 0xc1, 0xc0, 0x00, 0xd9, 0xde, 0x8c, 0x00, 0x15, 0xb0, 0xf2, 0xbf,
    0x5b, 0x42, 0x52, 0x4f, 0x4d, 0x5d, 0x20, 0x63, 0x72, 0x61, 0x73, 0x68, 0x65, 0x64, 0x0a, 0x00
};

static k_root g_kroot;

static int (*searchModule)(const char* name) = (void*)(0x588000 + 0x4e58 + 1);
static int (*getModule)(int pid, int uid, SceKernelModuleInfo* info) = (void*)(0x588000 + 0x267C + 1);

#include "utils.c" // misc
#include "cmep.c" // cmep-related code
#include "tz.c" // tz exec code

// alloc memblocks and get memcpy/memset
int k_init(k_root* kroot) {
    void (*memset)(void* dst, int ch, int sz) = KFUN("SceSysmem", 0x2424);
    if (!kroot || !memset)
        return -1;
    memset(kroot, 0, sizeof(k_root));
    kroot->memset = memset;
    kroot->memcpy = KFUN("SceSysmem", 0x700);
    kroot->printf = KFUN("SceSysmem", 0x1daf0 | 1);
    if (!kroot->memcpy || !kroot->printf)
        return -2;

    kroot->printf("[SNS][INIT] k_init started, allocing memblocks\n");

    int (*alloc_mb)(const char* name, int type, int size, alloc_mb_opt * opt) = KFUN("SceSysmem", 0xb958 | 1);
    int (*get_mb)(int uid, void *out_va) = KFUN("SceSysmem", 0x6ac8 | 1);

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

    int (*umemcpy)() = KFUN("SceSysmem", 0x1b259);
    umemcpy(&g_kroot, kroot, sizeof(k_root));
    return 0;
}

// free memblocks and cleanup
void k_uinit(k_root* kroot) {
    if (!kroot)
        return;
    if (kroot->printf)
        kroot->printf("[SNS][UINIT] k_uinit called, cleaning up\n");
    int (*free_mb)(int uid) = KFUN("SceSysmem", 0xbb50 | 1);
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
    kroot.printf("[SNS] k_init complete 10\n");

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

    // prepare the fake secure_kernel payload
    ret = brom_init(&kroot);
    kroot.printf("[SNS] brom_init ret 0x%X\n", ret);
    if (ret)
        goto kexit;

    // enable cmep reset from arm
    ret = cmep_run(&kroot, (void*)enable_reset_nmp, sizeof(enable_reset_nmp), 0x0003003F);
    kroot.printf("[SNS] cmep_run ret 0x%X\n", ret);
    if (ret < 0)
        goto kexit;

    // redirect the cmep->arm intr 0 handler
    uint32_t custom_cry0 = 0x00d2839;
    ret = tz_dacroff_copyto(&kroot, 0x00543200, &custom_cry0, 4);
    kroot.printf("[SNS] redir_cry0 ret 0x%X\n", ret);

reset_fud:
    // reset cmep with our fake secure_kernel
    kroot.printf("[SNS] calling fudreset smc\n");
    ret = xsmc(0x4C000000, 0, 0, 0, SMC_FUDRESET);
    kroot.printf("[SNS] smc_fudreset ret 0x%X\n", ret);
    if (ret != 0x421)
        goto kexit;

    // ----------start bootrom memes there

    // dump cmep mem
    kroot.printf("[SNS] dumping f00d uncached mem\n");
    ret = bromcpy(0x1C020000, 0x00040000, 0x20000, &kroot);
    kroot.printf("[SNS] bromcpy ret 0x%X\n", ret);
    if (ret)
        goto kexit;
    write_file("host0:cmep_mem.bin", kroot.tachyon_edram + 0x20000, 0x20000, 0, &kroot);

    // copy 3.65 second_loader to cmep memory
    int (*ukcpy)(void* dst, void* src, uint32_t size) = KFUN("SceSysmem", 0xa874 | 1);
    ukcpy(kroot.tachyon_edram + 0x40000, usl, 0xCE00);
    ret = apply_fakeenv(kroot.tachyon_edram + 0x40000, (void*)fakesl_evh, sizeof(fakesl_evh), &kroot);
    kroot.printf("[SNS] apply_fakeenv ret 0x%X\n", ret);
    if (ret)
        goto kexit;

    // copy the custom exception vectors handler
    kroot.memcpy(kroot.tachyon_edram + 0xF800, (void*)brom_crash_print_nmp, sizeof(brom_crash_print_nmp));
    ret = bromcpy(0x000400d0, 0x1c00F800, sizeof(brom_crash_print_nmp), &kroot);
    kroot.printf("[SNS] copy_brom_evh ret 0x%X\n", ret);
    if (ret)
        goto kexit;

    // run whatever bootrom code we need
    ret = brom_run(&kroot, (void *)fakesl_ccode_nmp, sizeof(fakesl_ccode_nmp), 0x4c000020, 0);
    kroot.printf("[SNS] ccode ret 0x%X\n", ret);
    if (ret < 0)
        goto kexit;

    /* reset cmep and run the code again
    volatile fm_nfo* fmnfo = kroot.tachyon_edram;
    kroot.memset((void*)fmnfo, 0, sizeof(fm_nfo));
    fmnfo->codepaddr = 0x00040000;
    fmnfo->magic = 0x14ff;
    fmnfo->status = 0x34;

    ret = brom_init(&kroot);
    kroot.printf("[SNS] brom_init ret 0x%X\n", ret);
    goto reset_fud;
    */

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