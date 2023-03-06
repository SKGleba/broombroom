typedef struct {
    uint32_t* addr;
    uint32_t length;
} __attribute__((packed)) region_t;

typedef struct {
    uint32_t unused_0[2];
    uint32_t use_lv2_mode_0; // if 1, use lv2 list
    uint32_t use_lv2_mode_1; // if 1, use lv2 list
    uint32_t unused_10[3];
    uint32_t list_count; // must be < 0x1F1
    uint32_t unused_20[4];
    uint32_t total_count; // only used in LV1 mode
    uint32_t unused_34[1];
    union {
        region_t lv1[0x3d0]; // 0x3d0
        region_t lv2[0x3d0];
    } list;
} __attribute__((packed)) cmd_0x50002_t;

typedef struct heap_hdr {
    void* data;
    uint32_t size;
    uint32_t size_aligned;
    uint32_t padding;
    struct NMPheap_hdr* prev;
    struct NMPheap_hdr* next;
} __attribute__((packed)) heap_hdr_t;

typedef struct SceSblSmCommContext130 {
    uint32_t unk_0;
    uint32_t self_type; // 2 - user = 1 / kernel = 0
    char data0[0x90]; //hardcoded data
    char data1[0x90];
    uint32_t pathId; // 2 (2 = os0)
    uint32_t unk_12C;
} SceSblSmCommContext130;

typedef struct smsched_call_sm_cmd {
    unsigned int size;
    unsigned int service_id;
    unsigned int response;
    unsigned int unk2;
    cmd_0x50002_t cargs;
} smsched_call_sm_cmd;

// sm_auth_info
static const unsigned char ctx_130_data[0x90] =
{
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x28, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
  0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x09,
  0x80, 0x03, 0x00, 0x00, 0xc3, 0x00, 0x00, 0x00, 0x80, 0x09,
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};