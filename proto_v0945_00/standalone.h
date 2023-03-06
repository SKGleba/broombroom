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
} k_root;

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

enum MEMBLOCK_CONSTRUCT {
    MB_A_RO = 0x4,
    MB_A_RX = 0x5,
    MB_A_RW = 0x6,
    MB_A_F = 0x7,
    MB_A_URO = 0x40,
    MB_A_URX = 0x50,
    MB_A_URW = 0x60,
    MB_A_UF = 0x70,
    MB_S_G = 0x200,
    MB_S_H = 0x800,
    MB_S_S = 0xD00,
    MB_C_LD = 0x2000,
    MB_C_HE = 0x4000,
    MB_C_N = 0x8000,
    MB_C_Y = 0xD000,
    MB_I_IO = 0x100000,
    MB_I_DEF = 0x200000,
    MB_I_CDR = 0x400000,
    MB_I_BU = 0x500000,
    MB_I_PC = 0x800000,
    MB_I_SHR = 0x900000,
    MB_I_CDLG = 0xA00000,
    MB_I_BK = 0xC00000,
    MB_I_PMM = 0xF00000,
    MB_U_CDRN = 0x5000000,
    MB_U_UNF = 0x6000000,
    MB_U_CDRD = 0x9000000,
    MB_U_SHR = 0xA000000,
    MB_U_IO = 0xB000000,
    MB_U_DEF = 0xC000000,
    MB_U_PC = 0xD000000,
    MB_U_CDLGP = 0xE000000,
    MB_U_CDLGV = 0xF000000,
    MB_K_DEF = 0x10000000,
    MB_K_IO = 0x20000000,
    MB_K_PC = 0x30000000,
    MB_K_CDRD = 0x40000000,
    MB_K_CDRN = 0x50000000,
    MB_K_UNF = 0x60000000,
    MB_K_GPU = 0xA0000000,
};

#define SCE_FREAD       (0x0001)  
#define SCE_FWRITE      (0x0002) 
#define SCE_FAPPEND     (0x0100)  
#define SCE_FAPPEND     (0x0100)  
#define SCE_FCREAT      (0x0200)  
#define SCE_O_RDONLY    (SCE_FREAD)
#define SCE_O_WRONLY    (SCE_FWRITE)
#define SCE_O_RDWR      (SCE_FREAD|SCE_FWRITE)
#define SCE_O_APPEND    (SCE_FAPPEND)
#define SCE_O_CREAT     (SCE_FCREAT) 
#define SCE_O_TRUNC		((0x0400))

typedef struct SceIoStat {
    uint32_t st_mode;
    unsigned int st_attr;
    uint32_t st_size;
    uint32_t st_ctime;
    uint32_t st_atime;
    uint32_t st_mtime;
    unsigned int st_private[6];
} SceIoStat;