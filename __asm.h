/*
 * Copyright 2019 Google LLC

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#pragma once
// assembly function declaration
#include <gvm_types.h>

extern u16 gvm_read_ldt(void);
extern void gvm_load_ldt(u16 sel);
extern void load_TR_desc(void);
extern u16 gvm_read_tr(void);
extern void gvm_load_tr(u16 sel);

#pragma warning(disable : 4210)
#define savesegment(seg, value) \
extern u16 save_##seg ##_segment(void); \
value = save_##seg ##_segment()

#define loadsegment(seg, value) \
extern u16 load_##seg ##_segment(u16 sel); \
load_##seg ##_segment(value)

extern void load_gs_index(u16 value);
extern void __asm_vmx_vcpu_run(void *vmx);
extern void __asm_vmx_handle_external_intr(size_t entry);

extern void __asm_svm_vcpu_run(void *svm);

extern void __int2(void);
extern void __int12(void);

//debug register
extern u64 __read_dr0();
extern u64 __read_dr1();
extern u64 __read_dr2();
extern u64 __read_dr3();
extern u64 __read_dr6();
extern u64 __read_dr7();
extern void __write_dr0(u64 val);
extern void __write_dr1(u64 val);
extern void __write_dr2(u64 val);
extern void __write_dr3(u64 val);
extern void __write_dr6(u64 val);
extern void __write_dr7(u64 val);

#define dr_read_case(regno) \
case regno: \
	val = __read_dr##regno(); \
	break

static __forceinline u64 __get_debugreg(int regno)
{
	u64 val = 0;

	switch (regno) {
		dr_read_case(0);
		dr_read_case(1);
		dr_read_case(2);
		dr_read_case(3);
		dr_read_case(6);
		dr_read_case(7);
	default:
		BUG();
	}
	return val;
}
#define get_debugreg(a, b) a = __get_debugreg(b)

#define dr_write_case(regno) \
case regno: \
	__write_dr##regno(val); \
	break

static __forceinline void set_debugreg(u64 val, int regno)
{
	switch (regno) {
		dr_write_case(0);
		dr_write_case(1);
		dr_write_case(2);
		dr_write_case(3);
		dr_write_case(6);
		dr_write_case(7);
	default:
		BUG();
	}
}

//mmx
extern void __asm_save_mm0(u64 *data);
extern void __asm_save_mm1(u64 *data);
extern void __asm_save_mm2(u64 *data);
extern void __asm_save_mm3(u64 *data);
extern void __asm_save_mm4(u64 *data);
extern void __asm_save_mm5(u64 *data);
extern void __asm_save_mm6(u64 *data);
extern void __asm_save_mm7(u64 *data);
extern void __asm_store_mm0(u64 *data);
extern void __asm_store_mm1(u64 *data);
extern void __asm_store_mm2(u64 *data);
extern void __asm_store_mm3(u64 *data);
extern void __asm_store_mm4(u64 *data);
extern void __asm_store_mm5(u64 *data);
extern void __asm_store_mm6(u64 *data);
extern void __asm_store_mm7(u64 *data);

//fpu
extern void __fninit(void);
extern void __fnstcw(u16 *fcw);
extern void __fnstsw(u16 *fcw);
extern void __fwait(void);
extern void __clts(void);

//bswap
extern void __bswap64(u64 *val);
extern void __bswap32(u32 *val);

#define read_cr0 __readcr0
#define read_cr3 __readcr3

#define stts() __writecr0(__readcr0() | X86_CR0_TS)

#define load_gdt(pdesc) _lgdt((void *)pdesc)
#define load_idt(pdesc) __lidt((void *)pdesc)

static __forceinline size_t cr4_read_shadow(void)
{
	return __readcr4();
}

static __forceinline void cr4_set_bits(size_t mask)
{
	size_t cr4 = __readcr4();

	if ((cr4 | mask) != cr4)
	{
		cr4 |= mask;
		__writecr4(cr4);
	}
}

static __forceinline void cr4_clear_bits(size_t mask)
{
	size_t cr4 = __readcr4();

	if ((cr4 & ~mask) != cr4)
	{
		cr4 &= ~mask;
		__writecr4(cr4);
	}
}

static __forceinline void native_store_gdt(void *gdt)
{
	_sgdt(gdt);
}

static __forceinline void native_store_idt(void *idt)
{
	__sidt(idt);
}

extern void __asm_invvpid(int ext, void *op);
extern void __asm_invept(int ext, void *op);

