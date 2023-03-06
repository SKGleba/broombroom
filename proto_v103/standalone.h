typedef struct k_root {
    int venezia_spram_mb;
    void* venezia_spram;
    int tachyon_edram_mb;
    void* tachyon_edram;
    int pac_dram_mb;
    void* pac_dram;
    void (*printf)();
    void (*memcpy)(void* dst, const void* src, int sz);
    void (*memset)(void* dst, int ch, int sz);
} __attribute__((packed)) k_root;

#define DACR_OFF(stmt)                 \
do {                                   \
    unsigned prev_dacr;                \
    __asm__ volatile(                  \
        "mrc p15, 0, %0, c3, c0, 0 \n" \
        : "=r" (prev_dacr)             \
    );                                 \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (0xFFFF0000)           \
    );                                 \
    stmt;                              \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (prev_dacr)            \
    );                                 \
} while (0)

typedef struct alloc_mb_opt { // 1.03 SceKernelAllocMemBlockKernelOpt
    uint32_t size;
    uint32_t field_4;
    uint32_t attr;
    uint32_t field_C;
    uint32_t paddr;
    uint32_t alignment;
    uint32_t extraLow;
    uint32_t extraHigh;
    uint32_t mirror_blockid;
    uint32_t pid;
    uint32_t paddr_list_vaddr;
    uint32_t field_2C;
} alloc_mb_opt;

typedef struct SceKernelSegmentInfo {
    unsigned int size;   //!< this structure size (0x18)
    unsigned int perms;  //!< probably rwx in low bits
    void* vaddr;    //!< address in memory
    unsigned int memsz;  //!< size in memory
    unsigned int filesz; //!< original size of memsz
    unsigned int res;    //!< unused
} SceKernelSegmentInfo;

typedef struct SceKernelModuleInfo {
    unsigned int size;
    unsigned int modid;
    uint16_t modattr;
    uint8_t  modver[2];
    char module_name[28];
    unsigned int unk28;
    void* start_entry;
    void* stop_entry;
    void* exit_entry;
    void* exidx_top;
    void* exidx_btm;
    void* extab_top;
    void* extab_btm;
    void* tlsInit;
    unsigned int tlsInitSize;
    unsigned int tlsAreaSize;
    char path[256];
    SceKernelSegmentInfo segments[4];
    unsigned int state;
} SceKernelModuleInfo;