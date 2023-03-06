/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "../spl-defs.h"
#include "sl_print.c"

// get keyslot protection
static u32_t __attribute__((optimize("O0"))) get_prot(u32_t slot) {
	*(volatile u32_t*)0xE0030028 = slot;
	asm volatile (
		"syncm\n"
		);
	return *(volatile u32_t*)0xE003002C;
}

// print the control bus and ks prots
u32_t __attribute__((section(".text.start"))) start(u32_t op_paddr) {
	// print the welcome string
	*(u32_t*)0x0004bc30 = (u32_t)0x474b530a;
	print_str(0x0004bc30);
	printu32(op_paddr, 0xfc);
	
	// create a tiny ret(cbus[a0]) func @ arg
	*(u32_t*)op_paddr = 0xf0147b1a;
	*(u32_t*)(op_paddr + 4) = 0x10be0000;
	u32_t(*get_cb)() = (void*)op_paddr;

	// print out the control bus
	u32_t buf = 0;
	for (u32_t num = 0; num < 0x10000; num -= -1) {
		*(volatile u16_t*)(op_paddr + 4) = (u16_t)num;
		buf = get_cb();
		if (buf)
			printu32(buf, num);
	}

	// separator
	printu32(0xd00d0001, 0xb00b);

	// print out the keyslot prots
	buf = 0;
	for (u32_t ks = 0; ks < 0x800; ks -= -1) {
		buf = get_prot(ks);
		if (buf)
			printu32(buf, ks);
	}

	//print the code end string
	print_str(0x0004bc31);
	print_str(0x0004c418);

	return 0;
}
