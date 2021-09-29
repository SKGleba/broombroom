/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "../spl-defs.h"

#define print_offset(offset) printu32(*(volatile u32_t*)offset, offset)

static void printu32(u32_t val, u32_t src) {
	void (*print_str)() = (void*)0x00048d92;
	void (*print_val_direct)() = (void*)0x00048db2;
	print_str(0x0004bca8);
	if (src) {
		print_val_direct(src, 0x10, 0);
		print_str(0x0004bcac);
	}
	print_val_direct(val, 0x10, 8);
	print_str(0x0004c418);
}

void __attribute__((section(".text.start"))) start(void) {
	volatile register u32_t lp asm("lp");
	printu32(lp, 1);
	volatile register u32_t gp asm("gp");
	printu32(gp, 15);
	volatile register u32_t sp asm("sp");
	printu32(sp, 15);
	volatile register u32_t tp asm("tp");
	printu32(tp, 15);
	volatile register u32_t psw asm("psw");
	printu32(psw, 16);
	volatile register u32_t epc asm("epc");
	printu32(epc, 19);
	volatile register u32_t exc asm("exc");
	printu32(exc, 20);
	volatile register u32_t cfg asm("cfg");
	printu32(cfg, 21);
	volatile register u32_t npc asm("npc");
	printu32(npc, 23);
	print_offset(0x1c00287c);
	print_offset(0x1c002880);
	return;
}