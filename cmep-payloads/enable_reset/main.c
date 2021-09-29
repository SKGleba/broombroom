/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "../spl-defs.h"
u32_t __attribute__((optimize("O0"))) _start(u32_t reset_mode) {
	*(volatile u32_t*)(0xE0020000) = reset_mode; // e001 if arm flags
	*(volatile u32_t*)(0xE0020004) = 0; // bootrom src
	return reset_mode;
}