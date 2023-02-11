/*
 * Copyright 2019 Google LLC
 */

#ifndef _ASM_X86_KVM_H
#define _ASM_X86_KVM_H

/*
 * kvm x86 specific structures and definitions
 *
 */

#include <aehd_types.h>

#define DE_VECTOR 0
#define DB_VECTOR 1
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define AC_VECTOR 17
#define MC_VECTOR 18
#define XM_VECTOR 19
#define VE_VECTOR 20

/* Select x86 specific features in <linux/kvm.h> */
#define __AEHD_HAVE_MSI
#define __AEHD_HAVE_USER_NMI
#define __AEHD_HAVE_GUEST_DEBUG
#define __AEHD_HAVE_MSIX
#define __AEHD_HAVE_VCPU_EVENTS
#define __AEHD_HAVE_DEBUGREGS
#define __AEHD_HAVE_XSAVE
#define __AEHD_HAVE_XCRS
#define __AEHD_HAVE_READONLY_MEM

/* Architectural interrupt line count. */
#define AEHD_NR_INTERRUPTS 256

struct kvm_memory_alias {
	__u32 slot;  /* this has a different namespace than memory slots */
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 target_phys_addr;
};

/* for AEHD_GET_IRQCHIP and AEHD_SET_IRQCHIP */
struct kvm_pic_state {
	__u8 last_irr;	/* edge detection */
	__u8 irr;		/* interrupt request register */
	__u8 imr;		/* interrupt mask register */
	__u8 isr;		/* interrupt service register */
	__u8 priority_add;	/* highest irq priority */
	__u8 irq_base;
	__u8 read_reg_select;
	__u8 poll;
	__u8 special_mask;
	__u8 init_state;
	__u8 auto_eoi;
	__u8 rotate_on_auto_eoi;
	__u8 special_fully_nested_mode;
	__u8 init4;		/* true if 4 byte init */
	__u8 elcr;		/* PIIX edge/trigger selection */
	__u8 elcr_mask;
};

#define AEHD_IOAPIC_NUM_PINS  24
struct kvm_ioapic_state {
	__u64 base_address;
	__u32 ioregsel;
	__u32 id;
	__u32 irr;
	__u32 pad;
	union {
		__u64 bits;
		struct {
			__u8 vector;
			__u8 delivery_mode:3;
			__u8 dest_mode:1;
			__u8 delivery_status:1;
			__u8 polarity:1;
			__u8 remote_irr:1;
			__u8 trig_mode:1;
			__u8 mask:1;
			__u8 reserve:7;
			__u8 reserved[4];
			__u8 dest_id;
		} fields;
	} redirtbl[AEHD_IOAPIC_NUM_PINS];
};

#define AEHD_IRQCHIP_PIC_MASTER   0
#define AEHD_IRQCHIP_PIC_SLAVE    1
#define AEHD_IRQCHIP_IOAPIC       2
#define AEHD_NR_IRQCHIPS          3

#define AEHD_RUN_X86_SMM		 (1 << 0)

/* for AEHD_GET_REGS and AEHD_SET_REGS */
struct kvm_regs {
	/* out (AEHD_GET_REGS) / in (AEHD_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

/* for AEHD_GET_LAPIC and AEHD_SET_LAPIC */
#define AEHD_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
	char regs[AEHD_APIC_REG_SIZE];
};

struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct kvm_dtable {
	__u64 base;
	__u16 limit;
	__u16 padding[3];
};


/* for AEHD_GET_SREGS and AEHD_SET_SREGS */
struct kvm_sregs {
	/* out (AEHD_GET_SREGS) / in (AEHD_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[(AEHD_NR_INTERRUPTS + 63) / 64];
};

/* for AEHD_GET_FPU and AEHD_SET_FPU */
struct kvm_fpu {
	__u8  fpr[8][16];
	__u16 fcw;
	__u16 fsw;
	__u8  ftwx;  /* in fxsave format */
	__u8  pad1;
	__u16 last_opcode;
	__u64 last_ip;
	__u64 last_dp;
	__u8  xmm[16][16];
	__u32 mxcsr;
	__u32 pad2;
};

struct kvm_msr_entry {
	__u32 index;
	__u32 reserved;
	__u64 data;
};

#pragma warning(disable : 4200)
/* for AEHD_GET_MSRS and AEHD_SET_MSRS */
struct kvm_msrs {
	__u32 nmsrs; /* number of msrs in entries */
	__u32 pad;

	struct kvm_msr_entry entries[0];
};

/* for AEHD_GET_MSR_INDEX_LIST */
struct kvm_msr_list {
	__u32 nmsrs; /* number of msrs in entries */
	__u32 indices[0];
};

struct kvm_cpuid_entry {
	__u32 function;
	__u32 index;
	__u32 flags;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding[3];
};

#define AEHD_CPUID_FLAG_SIGNIFCANT_INDEX		(1 << 0)
#define AEHD_CPUID_FLAG_STATEFUL_FUNC		(1 << 1)
#define AEHD_CPUID_FLAG_STATE_READ_NEXT		(1 << 2)

/* for AEHD_SET_CPUID */
struct kvm_cpuid {
	__u32 nent;
	__u32 padding;
	struct kvm_cpuid_entry entries[0];
};

/* for AEHD_GET_PIT and AEHD_SET_PIT */
struct kvm_pit_channel_state {
	__u32 count; /* can be 65536 */
	__u16 latched_count;
	__u8 count_latched;
	__u8 status_latched;
	__u8 status;
	__u8 read_state;
	__u8 write_state;
	__u8 write_latch;
	__u8 rw_mode;
	__u8 mode;
	__u8 bcd;
	__u8 gate;
	__s64 count_load_time;
};

struct kvm_debug_exit_arch {
	__u32 exception;
	__u32 pad;
	__u64 pc;
	__u64 dr6;
	__u64 dr7;
};

#define AEHD_GUESTDBG_USE_SW_BP		0x00010000
#define AEHD_GUESTDBG_USE_HW_BP		0x00020000
#define AEHD_GUESTDBG_INJECT_DB		0x00040000
#define AEHD_GUESTDBG_INJECT_BP		0x00080000

/* for AEHD_SET_GUEST_DEBUG */
struct kvm_guest_debug_arch {
	__u64 debugreg[8];
};

struct kvm_reinject_control {
	__u8 pit_reinject;
	__u8 reserved[31];
};

/* When set in flags, include corresponding fields on AEHD_SET_VCPU_EVENTS */
#define AEHD_VCPUEVENT_VALID_NMI_PENDING	0x00000001
#define AEHD_VCPUEVENT_VALID_SIPI_VECTOR	0x00000002
#define AEHD_VCPUEVENT_VALID_SHADOW	0x00000004
#define AEHD_VCPUEVENT_VALID_SMM		0x00000008

/* Interrupt shadow states */
#define AEHD_X86_SHADOW_INT_MOV_SS	0x01
#define AEHD_X86_SHADOW_INT_STI		0x02

/* for AEHD_GET/SET_VCPU_EVENTS */
struct kvm_vcpu_events {
	struct {
		__u8 injected;
		__u8 nr;
		__u8 has_error_code;
		__u8 pad;
		__u32 error_code;
	} exception;
	struct {
		__u8 injected;
		__u8 nr;
		__u8 soft;
		__u8 shadow;
	} interrupt;
	struct {
		__u8 injected;
		__u8 pending;
		__u8 masked;
		__u8 pad;
	} nmi;
	__u32 sipi_vector;
	__u32 flags;
	struct {
		__u8 smm;
		__u8 pending;
		__u8 smm_inside_nmi;
		__u8 latched_init;
	} smi;
	__u32 reserved[9];
};

/* for AEHD_GET/SET_DEBUGREGS */
struct kvm_debugregs {
	__u64 db[4];
	__u64 dr6;
	__u64 dr7;
	__u64 flags;
	__u64 reserved[9];
};

/* for AEHD_CAP_XSAVE */
struct kvm_xsave {
	__u32 region[1024];
};

#define AEHD_MAX_XCRS	16

struct kvm_xcr {
	__u32 xcr;
	__u32 reserved;
	__u64 value;
};

struct kvm_xcrs {
	__u32 nr_xcrs;
	__u32 flags;
	struct kvm_xcr xcrs[AEHD_MAX_XCRS];
	__u64 padding[16];
};

/* definition of registers in kvm_run */
struct kvm_sync_regs {
	u64 reg;
};

#define AEHD_X86_QUIRK_LINT0_REENABLED	(1 << 0)
#define AEHD_X86_QUIRK_CD_NW_CLEARED	(1 << 1)

#endif /* _ASM_X86_KVM_H */
