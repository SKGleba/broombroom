/*
 * Copyright (C) 2021 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "../spl-defs.h"

typedef struct {
	u32_t magic;
	u32_t src;
	u32_t dst;
	u32_t sz;
} __attribute__((packed)) bromcpy_args;

u32_t _start(bromcpy_args *args) {
	if (!args)
		return (u32_t)0xF00DBADA;
	if (args->magic != 0xF00DF00D)
		return (u32_t)0xF00DBADF;

	for (u32_t off = 0; off < args->sz; off-=-4) {
		*(u32_t*)(args->dst + off) = *(u32_t*)(args->src + off);
	}
	
	return (u32_t)0xF00D600D;
}