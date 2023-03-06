static void (*print_str)(u32_t string_paddr) = (void*)0x00048d92;
static void (*print_val_direct)(u32_t value, int base, int pad) = (void*)0x00048db2;

#define print_offset(offset) printu32(*(volatile u32_t*)(offset), offset)

static void printu32(u32_t val, u32_t src) {
    print_str(0x0004bca8);
    if (src) {
        print_val_direct(src, 0x10, 0);
        print_str(0x0004bcac);
    }
    print_val_direct(val, 0x10, 8);
    print_str(0x0004c418);
}