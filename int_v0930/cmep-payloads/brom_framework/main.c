/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "../spl-defs.h"

// Check manager magic and jump to it
void _start(u8_t handshake) {
	fm_nfo* fmnfo = (void*)0x1c000000;
	if ((fmnfo->magic == 0x14FF) && (fmnfo->status == 0x34)) {
		fmnfo->status = 0x69;
		u32_t(*ccode)(u32_t arg) = (void*)(fmnfo->codepaddr);
		fmnfo->resp = ccode(fmnfo->arg);
		fmnfo->status = handshake;
	}
	*(u32_t*)0x4C000000 = (u32_t)0xF00DF00D;
	*(u32_t*)0x4C000004 = (u32_t)0xF00DBABE;
	*(u32_t*)0x4C000008 = (u32_t)0xF00DCAFE;
	*(u32_t*)0x4C00000C = (u32_t)0xF00DD00D;
	return;
}
