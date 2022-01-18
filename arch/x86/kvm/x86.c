/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * derived from drivers/kvm/kvm_main.c
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright (C) 2008 Qumranet, Inc.
 * Copyright IBM Corporation, 2008
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 * Copyright 2019 Google LLC
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Amit Shah    <amit.shah@qumranet.com>
 *   Ben-Ami Yassour <benami@il.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <gvm_types.h>
#include <ntkrutils.h>
#include <gvm-main.h>
#include <linux/kvm_host.h>
#include "irq.h"
#include "mmu.h"
#include "tss.h"
#include "kvm_cache_regs.h"
#include "x86.h"
#include "cpuid.h"
#include "pmu.h"
#include <asm/vmx.h>


#define MAX_IO_MSRS 256

#define emul_to_vcpu(ctxt) \
	container_of(ctxt, struct kvm_vcpu, arch.emulate_ctxt)

/* EFER defaults:
 * - enable syscall per default because its emulated by kvm
 * - enable LME and LMA per default on 64 bit kvm
 */
#ifdef CONFIG_X86_64
static
u64 __read_mostly efer_reserved_bits = ~((u64)(EFER_SCE | EFER_LME | EFER_LMA));
#else
static u64 __read_mostly efer_reserved_bits = ~((u64)EFER_SCE);
#endif

#define VM_STAT(x) offsetof(struct kvm, stat.x), GVM_STAT_VM
#define VCPU_STAT(x) offsetof(struct kvm_vcpu, stat.x), GVM_STAT_VCPU

#define GVM_X2APIC_API_VALID_FLAGS (GVM_X2APIC_API_USE_32BIT_IDS | \
                                    GVM_X2APIC_API_DISABLE_BROADCAST_QUIRK)

static void update_cr8_intercept(struct kvm_vcpu *vcpu);
static void process_nmi(struct kvm_vcpu *vcpu);
static void enter_smm(struct kvm_vcpu *vcpu);
static void __kvm_set_rflags(struct kvm_vcpu *vcpu, size_t rflags);

struct kvm_x86_ops *kvm_x86_ops __read_mostly;

static bool __read_mostly ignore_msrs = 0;

unsigned int min_timer_period_us = 500;

/* tsc tolerance in parts per million - default to 1/2 of the NTP threshold */
static u32 __read_mostly tsc_tolerance_ppm = 250;

/* lapic timer advance (tscdeadline mode only) in nanoseconds */
unsigned int __read_mostly lapic_timer_advance_ns = 0;

static bool __read_mostly vector_hashing = true;

static bool __read_mostly backwards_tsc_observed = false;

u64 __read_mostly host_xcr0;

u64 kvm_get_apic_base(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic_base;
}

int kvm_set_apic_base(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	u64 old_state = vcpu->arch.apic_base &
		(MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	u64 new_state = msr_info->data &
		(MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	u64 reserved_bits = ((~0ULL) << cpuid_maxphyaddr(vcpu)) |
		0x2ff | (guest_cpuid_has_x2apic(vcpu) ? 0 : X2APIC_ENABLE);

	if (!msr_info->host_initiated &&
	    ((msr_info->data & reserved_bits) != 0 ||
	     new_state == X2APIC_ENABLE ||
	     (new_state == MSR_IA32_APICBASE_ENABLE &&
	      old_state == (MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE)) ||
	     (new_state == (MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE) &&
	      old_state == 0)))
		return 1;

	kvm_lapic_set_base(vcpu, msr_info->data);
	return 0;
}

#define EXCPT_BENIGN		0
#define EXCPT_CONTRIBUTORY	1
#define EXCPT_PF		2

static int exception_class(int vector)
{
	switch (vector) {
	case PF_VECTOR:
		return EXCPT_PF;
	case DE_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
		return EXCPT_CONTRIBUTORY;
	default:
		break;
	}
	return EXCPT_BENIGN;
}

#define EXCPT_FAULT		0
#define EXCPT_TRAP		1
#define EXCPT_ABORT		2
#define EXCPT_INTERRUPT		3

static int exception_type(int vector)
{
	unsigned int mask;

	if (WARN_ON(vector > 31 || vector == NMI_VECTOR))
		return EXCPT_INTERRUPT;

	mask = 1 << vector;

	/* #DB is trap, as instruction watchpoints are handled elsewhere */
	if (mask & ((1 << DB_VECTOR) | (1 << BP_VECTOR) | (1 << OF_VECTOR)))
		return EXCPT_TRAP;

	if (mask & ((1 << DF_VECTOR) | (1 << MC_VECTOR)))
		return EXCPT_ABORT;

	/* Reserved exceptions will result in fault */
	return EXCPT_FAULT;
}

static void kvm_multiple_exception(struct kvm_vcpu *vcpu,
		unsigned nr, bool has_error, u32 error_code,
		bool reinject)
{
	u32 prev_nr;
	int class1, class2;

	kvm_make_request(GVM_REQ_EVENT, vcpu);

	if (!vcpu->arch.exception.pending) {
	queue:
		if (has_error && !is_protmode(vcpu))
			has_error = false;
		vcpu->arch.exception.pending = true;
		vcpu->arch.exception.has_error_code = has_error;
		vcpu->arch.exception.nr = nr;
		vcpu->arch.exception.error_code = error_code;
		vcpu->arch.exception.reinject = reinject;
		return;
	}

	/* to check exception */
	prev_nr = vcpu->arch.exception.nr;
	if (prev_nr == DF_VECTOR) {
		/* triple fault -> shutdown */
		kvm_make_request(GVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	class1 = exception_class(prev_nr);
	class2 = exception_class(nr);
	if ((class1 == EXCPT_CONTRIBUTORY && class2 == EXCPT_CONTRIBUTORY)
		|| (class1 == EXCPT_PF && class2 != EXCPT_BENIGN)) {
		/* generate double fault per SDM Table 5-5 */
		vcpu->arch.exception.pending = true;
		vcpu->arch.exception.has_error_code = true;
		vcpu->arch.exception.nr = DF_VECTOR;
		vcpu->arch.exception.error_code = 0;
	} else
		/* replace previous exception with a new one in a hope
		   that instruction re-execution will regenerate lost
		   exception */
		goto queue;
}

void kvm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	kvm_multiple_exception(vcpu, nr, false, 0, false);
}

void kvm_requeue_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	kvm_multiple_exception(vcpu, nr, false, 0, true);
}

void kvm_complete_insn_gp(struct kvm_vcpu *vcpu, int err)
{
	if (err)
		kvm_inject_gp(vcpu, 0);
	else
		kvm_x86_ops->skip_emulated_instruction(vcpu);
}

void kvm_inject_page_fault(struct kvm_vcpu *vcpu, struct x86_exception *fault)
{
	++vcpu->stat.pf_guest;
	vcpu->arch.cr2 = fault->address;
	kvm_queue_exception_e(vcpu, PF_VECTOR, fault->error_code);
}

static bool kvm_propagate_fault(struct kvm_vcpu *vcpu, struct x86_exception *fault)
{
	if (mmu_is_nested(vcpu) && !fault->nested_page_fault)
		vcpu->arch.nested_mmu.inject_page_fault(vcpu, fault);
	else
		vcpu->arch.mmu.inject_page_fault(vcpu, fault);

	return fault->nested_page_fault;
}

void kvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	atomic_inc(&vcpu->arch.nmi_queued);
	kvm_make_request(GVM_REQ_NMI, vcpu);
}

void kvm_queue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, u32 error_code)
{
	kvm_multiple_exception(vcpu, nr, true, error_code, false);
}

void kvm_requeue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, u32 error_code)
{
	kvm_multiple_exception(vcpu, nr, true, error_code, true);
}

/*
 * Checks if cpl <= required_cpl; if true, return true.  Otherwise queue
 * a #GP and return false.
 */
bool kvm_require_cpl(struct kvm_vcpu *vcpu, int required_cpl)
{
	if (kvm_x86_ops->get_cpl(vcpu) <= required_cpl)
		return true;
	kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
	return false;
}

bool kvm_require_dr(struct kvm_vcpu *vcpu, int dr)
{
	if ((dr != 4 && dr != 5) || !kvm_read_cr4_bits(vcpu, X86_CR4_DE))
		return true;

	kvm_queue_exception(vcpu, UD_VECTOR);
	return false;
}

/*
 * This function will be used to read from the physical memory of the currently
 * running guest. The difference to kvm_vcpu_read_guest_page is that this function
 * can read from guest physical or from the guest's guest physical memory.
 */
int kvm_read_guest_page_mmu(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			    gfn_t ngfn, void *data, int offset, int len,
			    u32 access)
{
	struct x86_exception exception;
	gfn_t real_gfn;
	gpa_t ngpa;

	ngpa     = gfn_to_gpa(ngfn);
	real_gfn = mmu->translate_gpa(vcpu, ngpa, access, &exception);
	if (real_gfn == UNMAPPED_GVA)
		return -EFAULT;

	real_gfn = gpa_to_gfn(real_gfn);

	return kvm_vcpu_read_guest_page(vcpu, real_gfn, data, offset, len);
}

static int kvm_read_nested_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn,
			       void *data, int offset, int len, u32 access)
{
	return kvm_read_guest_page_mmu(vcpu, vcpu->arch.walk_mmu, gfn,
				       data, offset, len, access);
}

/*
 * Load the pae pdptrs.  Return true is they are all valid.
 */
int load_pdptrs(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu, size_t cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGE_SHIFT;
	unsigned offset = ((cr3 & (PAGE_SIZE-1)) >> 5) << 2;
	int i;
	int ret;
	u64 pdpte[ARRAY_SIZE(mmu->pdptrs)];

	ret = kvm_read_guest_page_mmu(vcpu, mmu, pdpt_gfn, pdpte,
				      offset * sizeof(u64), sizeof(pdpte),
				      PFERR_USER_MASK|PFERR_WRITE_MASK);
	if (ret < 0) {
		ret = 0;
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(pdpte); ++i) {
		if ((pdpte[i] & PT_PRESENT_MASK) &&
		    (pdpte[i] &
		     vcpu->arch.mmu.guest_rsvd_check.rsvd_bits_mask[0][2])) {
			ret = 0;
			goto out;
		}
	}
	ret = 1;

	memcpy(mmu->pdptrs, pdpte, sizeof(mmu->pdptrs));
	__set_bit(VCPU_EXREG_PDPTR,
		  (size_t *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR,
		  (size_t *)&vcpu->arch.regs_dirty);
out:

	return ret;
}

static bool pdptrs_changed(struct kvm_vcpu *vcpu)
{
	u64 pdpte[ARRAY_SIZE(vcpu->arch.walk_mmu->pdptrs)];
	bool changed = true;
	int offset;
	gfn_t gfn;
	int r;

	if (is_long_mode(vcpu) || !is_pae(vcpu))
		return false;

	if (!test_bit(VCPU_EXREG_PDPTR,
		      (size_t *)&vcpu->arch.regs_avail))
		return true;

	gfn = (kvm_read_cr3(vcpu) & ~31u) >> PAGE_SHIFT;
	offset = (kvm_read_cr3(vcpu) & ~31u) & (PAGE_SIZE - 1);
	r = kvm_read_nested_guest_page(vcpu, gfn, pdpte, offset, sizeof(pdpte),
				       PFERR_USER_MASK | PFERR_WRITE_MASK);
	if (r < 0)
		goto out;
	changed = memcmp(pdpte, vcpu->arch.walk_mmu->pdptrs, sizeof(pdpte)) != 0;
out:

	return changed;
}

int kvm_set_cr0(struct kvm_vcpu *vcpu, size_t cr0)
{
	size_t old_cr0 = kvm_read_cr0(vcpu);
	size_t update_bits = X86_CR0_PG | X86_CR0_WP;

	cr0 |= X86_CR0_ET;

#ifdef CONFIG_X86_64
	if (cr0 & 0xffffffff00000000UL)
		return 1;
#endif

	cr0 &= ~CR0_RESERVED_BITS;

	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD))
		return 1;

	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE))
		return 1;

	if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
#ifdef CONFIG_X86_64
		if ((vcpu->arch.efer & EFER_LME)) {
			int cs_db, cs_l;

			if (!is_pae(vcpu))
				return 1;
			kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
			if (cs_l)
				return 1;
		} else
#endif
		if (is_pae(vcpu) && !load_pdptrs(vcpu, vcpu->arch.walk_mmu,
						 kvm_read_cr3(vcpu)))
			return 1;
	}

	if (!(cr0 & X86_CR0_PG) && kvm_read_cr4_bits(vcpu, X86_CR4_PCIDE))
		return 1;

	kvm_x86_ops->set_cr0(vcpu, cr0);

	if ((cr0 ^ old_cr0) & update_bits)
		kvm_mmu_reset_context(vcpu);

	if (((cr0 ^ old_cr0) & X86_CR0_CD) &&
	    //kvm_arch_has_noncoherent_dma(vcpu->kvm) &&
	    !kvm_check_has_quirk(vcpu->kvm, GVM_X86_QUIRK_CD_NW_CLEARED))
		kvm_zap_gfn_range(vcpu->kvm, 0, ~0ULL);

	return 0;
}

void kvm_lmsw(struct kvm_vcpu *vcpu, size_t msw)
{
	(void)kvm_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~0x0eul) | (msw & 0x0f));
}

static void kvm_load_guest_xcr0(struct kvm_vcpu *vcpu)
{
	if (kvm_read_cr4_bits(vcpu, X86_CR4_OSXSAVE) &&
			!vcpu->guest_xcr0_loaded) {
		/* kvm_set_xcr() also depends on this */
		xsetbv(XCR_XFEATURE_ENABLED_MASK, vcpu->arch.xcr0);
		vcpu->guest_xcr0_loaded = 1;
	}
}

static void kvm_put_guest_xcr0(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_xcr0_loaded) {
		if (vcpu->arch.xcr0 != host_xcr0)
			xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		vcpu->guest_xcr0_loaded = 0;
	}
}

static int __kvm_set_xcr(struct kvm_vcpu *vcpu, u32 index, u64 xcr)
{
	u64 xcr0 = xcr;
	u64 old_xcr0 = vcpu->arch.xcr0;
	u64 valid_bits;

	/* Only support XCR_XFEATURE_ENABLED_MASK(xcr0) now  */
	if (index != XCR_XFEATURE_ENABLED_MASK)
		return 1;
	if (!(xcr0 & XFEATURE_MASK_FP))
		return 1;
	if ((xcr0 & XFEATURE_MASK_YMM) && !(xcr0 & XFEATURE_MASK_SSE))
		return 1;

	/*
	 * Do not allow the guest to set bits that we do not support
	 * saving.  However, xcr0 bit 0 is always set, even if the
	 * emulated CPU does not support XSAVE (see fx_init).
	 */
	valid_bits = vcpu->arch.guest_supported_xcr0 | XFEATURE_MASK_FP;
	if (xcr0 & ~valid_bits)
		return 1;

	if ((!(xcr0 & XFEATURE_MASK_BNDREGS)) !=
	    (!(xcr0 & XFEATURE_MASK_BNDCSR)))
		return 1;

	if (xcr0 & XFEATURE_MASK_AVX512) {
		if (!(xcr0 & XFEATURE_MASK_YMM))
			return 1;
		if ((xcr0 & XFEATURE_MASK_AVX512) != XFEATURE_MASK_AVX512)
			return 1;
	}
	vcpu->arch.xcr0 = xcr0;

	if ((xcr0 ^ old_xcr0) & XFEATURE_MASK_EXTEND)
		kvm_update_cpuid(vcpu);
	return 0;
}

int kvm_set_xcr(struct kvm_vcpu *vcpu, u32 index, u64 xcr)
{
	if (kvm_x86_ops->get_cpl(vcpu) != 0 ||
	    __kvm_set_xcr(vcpu, index, xcr)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}
	return 0;
}

int kvm_set_cr4(struct kvm_vcpu *vcpu, size_t cr4)
{
	size_t old_cr4 = kvm_read_cr4(vcpu);
	size_t pdptr_bits = X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE |
				   X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE;

	if (cr4 & CR4_RESERVED_BITS)
		return 1;

	if (!guest_cpuid_has_xsave(vcpu) && (cr4 & X86_CR4_OSXSAVE))
		return 1;

	if (!guest_cpuid_has_smep(vcpu) && (cr4 & X86_CR4_SMEP))
		return 1;

	if (!guest_cpuid_has_smap(vcpu) && (cr4 & X86_CR4_SMAP))
		return 1;

	if (!guest_cpuid_has_fsgsbase(vcpu) && (cr4 & X86_CR4_FSGSBASE))
		return 1;

	if (!guest_cpuid_has_pku(vcpu) && (cr4 & X86_CR4_PKE))
		return 1;

	if (is_long_mode(vcpu)) {
		if (!(cr4 & X86_CR4_PAE))
			return 1;
	} else if (is_paging(vcpu) && (cr4 & X86_CR4_PAE)
		   && ((cr4 ^ old_cr4) & pdptr_bits)
		   && !load_pdptrs(vcpu, vcpu->arch.walk_mmu,
				   kvm_read_cr3(vcpu)))
		return 1;

	if ((cr4 & X86_CR4_PCIDE) && !(old_cr4 & X86_CR4_PCIDE)) {
		if (!guest_cpuid_has_pcid(vcpu))
			return 1;

		/* PCID can not be enabled when cr3[11:0]!=000H or EFER.LMA=0 */
		if ((kvm_read_cr3(vcpu) & X86_CR3_PCID_MASK) || !is_long_mode(vcpu))
			return 1;
	}

	if (kvm_x86_ops->set_cr4(vcpu, cr4))
		return 1;

	if (((cr4 ^ old_cr4) & pdptr_bits) ||
	    (!(cr4 & X86_CR4_PCIDE) && (old_cr4 & X86_CR4_PCIDE)))
		kvm_mmu_reset_context(vcpu);

	if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		kvm_update_cpuid(vcpu);

	return 0;
}

int kvm_set_cr3(struct kvm_vcpu *vcpu, size_t cr3)
{
#ifdef CONFIG_X86_64
	cr3 &= ~CR3_PCID_INVD;
#endif

	if (cr3 == kvm_read_cr3(vcpu) && !pdptrs_changed(vcpu)) {
		kvm_mmu_sync_roots(vcpu);
		kvm_make_request(GVM_REQ_TLB_FLUSH, vcpu);
		return 0;
	}

	if (is_long_mode(vcpu)) {
		if (cr3 & CR3_L_MODE_RESERVED_BITS)
			return 1;
	} else if (is_pae(vcpu) && is_paging(vcpu) &&
		   !load_pdptrs(vcpu, vcpu->arch.walk_mmu, cr3))
		return 1;

	vcpu->arch.cr3 = cr3;
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);
	kvm_mmu_new_cr3(vcpu);
	return 0;
}

int kvm_set_cr8(struct kvm_vcpu *vcpu, size_t cr8)
{
	if (cr8 & CR8_RESERVED_BITS)
		return 1;
	if (lapic_in_kernel(vcpu))
		kvm_lapic_set_tpr(vcpu, cr8);
	else
		vcpu->arch.cr8 = cr8;
	return 0;
}

size_t kvm_get_cr8(struct kvm_vcpu *vcpu)
{
	if (lapic_in_kernel(vcpu))
		return kvm_lapic_get_cr8(vcpu);
	else
		return vcpu->arch.cr8;
}

static void kvm_update_dr0123(struct kvm_vcpu *vcpu)
{
	int i;

	if (!(vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP)) {
		for (i = 0; i < GVM_NR_DB_REGS; i++)
			vcpu->arch.eff_db[i] = vcpu->arch.db[i];
		vcpu->arch.switch_db_regs |= GVM_DEBUGREG_RELOAD;
	}
}

static void kvm_update_dr6(struct kvm_vcpu *vcpu)
{
	if (!(vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP))
		kvm_x86_ops->set_dr6(vcpu, vcpu->arch.dr6);
}

static void kvm_update_dr7(struct kvm_vcpu *vcpu)
{
	size_t dr7;

	if (vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP)
		dr7 = vcpu->arch.guest_debug_dr7;
	else
		dr7 = vcpu->arch.dr7;
	kvm_x86_ops->set_dr7(vcpu, dr7);
	vcpu->arch.switch_db_regs &= ~GVM_DEBUGREG_BP_ENABLED;
	if (dr7 & DR7_BP_EN_MASK)
		vcpu->arch.switch_db_regs |= GVM_DEBUGREG_BP_ENABLED;
}

static u64 kvm_dr6_fixed(struct kvm_vcpu *vcpu)
{
	u64 fixed = DR6_FIXED_1;

	if (!guest_cpuid_has_rtm(vcpu))
		fixed |= DR6_RTM;
	return fixed;
}

static int __kvm_set_dr(struct kvm_vcpu *vcpu, int dr, size_t val)
{
	switch (dr) {
	case 0:
	case 1:
	case 2:
	case 3:
		vcpu->arch.db[dr] = val;
		if (!(vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP))
			vcpu->arch.eff_db[dr] = val;
		break;
	case 4:
		/* fall through */
	case 6:
		if (val & 0xffffffff00000000ULL)
			return -1; /* #GP */
		vcpu->arch.dr6 = (val & DR6_VOLATILE) | kvm_dr6_fixed(vcpu);
		kvm_update_dr6(vcpu);
		break;
	case 5:
		/* fall through */
	default: /* 7 */
		if (val & 0xffffffff00000000ULL)
			return -1; /* #GP */
		vcpu->arch.dr7 = (val & DR7_VOLATILE) | DR7_FIXED_1;
		kvm_update_dr7(vcpu);
		break;
	}

	return 0;
}

int kvm_set_dr(struct kvm_vcpu *vcpu, int dr, size_t val)
{
	if (__kvm_set_dr(vcpu, dr, val)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}
	return 0;
}

int kvm_get_dr(struct kvm_vcpu *vcpu, int dr, size_t *val)
{
	switch (dr) {
	case 0:
	case 1:
	case 2:
	case 3:
		*val = vcpu->arch.db[dr];
		break;
	case 4:
		/* fall through */
	case 6:
		if (vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP)
			*val = vcpu->arch.dr6;
		else
			*val = kvm_x86_ops->get_dr6(vcpu);
		break;
	case 5:
		/* fall through */
	default: /* 7 */
		*val = vcpu->arch.dr7;
		break;
	}
	return 0;
}

#if 0
bool kvm_rdpmc(struct kvm_vcpu *vcpu)
{
	u32 ecx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	u64 data;
	int err;

	err = kvm_pmu_rdpmc(vcpu, ecx, &data);
	if (err)
		return err;
	kvm_register_write(vcpu, VCPU_REGS_RAX, (u32)data);
	kvm_register_write(vcpu, VCPU_REGS_RDX, data >> 32);
	return err;
}
#endif

/*
 * List of msr numbers which we expose to userspace through GVM_GET_MSRS
 * and GVM_SET_MSRS, and GVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu. This capabilities test skips MSRs that are
 * kvm-specific. Those are put in emulated_msrs; filtering of emulated_msrs
 * may depend on host virtualization features rather than host cpu features.
 */

static u32 msrs_to_save[] = {
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_STAR,
#ifdef CONFIG_X86_64
	MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
#endif
	MSR_IA32_TSC, MSR_IA32_CR_PAT, //MSR_VM_HSAVE_PA,
	MSR_IA32_FEATURE_CONTROL, //MSR_IA32_BNDCFGS, MSR_TSC_AUX,
};

static unsigned num_msrs_to_save;

bool kvm_valid_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	if (efer & efer_reserved_bits)
		return false;

	if (efer & EFER_FFXSR) {
		struct kvm_cpuid_entry *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->edx & bit(X86_FEATURE_FXSR_OPT)))
			return false;
	}

	if (efer & EFER_SVME) {
		struct kvm_cpuid_entry *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->ecx & bit(X86_FEATURE_SVM)))
			return false;
	}

	return true;
}

static int set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	u64 old_efer = vcpu->arch.efer;

	if (!kvm_valid_efer(vcpu, efer))
		return 1;

	if (is_paging(vcpu)
	    && (vcpu->arch.efer & EFER_LME) != (efer & EFER_LME))
		return 1;

	efer &= ~EFER_LMA;
	efer |= vcpu->arch.efer & EFER_LMA;

	kvm_x86_ops->set_efer(vcpu, efer);

	/* Update reserved bits */
	if ((efer ^ old_efer) & EFER_NX)
		kvm_mmu_reset_context(vcpu);

	return 0;
}

void kvm_enable_efer_bits(u64 mask)
{
       efer_reserved_bits &= ~mask;
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	switch (msr->index) {
	case MSR_FS_BASE:
	case MSR_GS_BASE:
	case MSR_KERNEL_GS_BASE:
	case MSR_CSTAR:
	case MSR_LSTAR:
		if (is_noncanonical_address(msr->data))
			return 1;
		break;
	case MSR_IA32_SYSENTER_EIP:
	case MSR_IA32_SYSENTER_ESP:
		/*
		 * IA32_SYSENTER_ESP and IA32_SYSENTER_EIP cause #GP if
		 * non-canonical address is written on Intel but not on
		 * AMD (which ignores the top 32-bits, because it does
		 * not implement 64-bit SYSENTER).
		 *
		 * 64-bit code should hence be able to write a non-canonical
		 * value on AMD.  Making the address canonical ensures that
		 * vmentry does not fail on Intel after writing a non-canonical
		 * value, and that something deterministic happens if the guest
		 * invokes 64-bit SYSENTER.
		 */
		msr->data = get_canonical(msr->data);
	}
	return kvm_x86_ops->set_msr(vcpu, msr);
}

/*
 * Adapt set_msr() to msr_io()'s calling convention
 */
static int do_get_msr(struct kvm_vcpu *vcpu, unsigned index, u64 *data)
{
	struct msr_data msr;
	int r;

	msr.index = index;
	msr.host_initiated = true;
	r = kvm_get_msr(vcpu, &msr);
	if (r)
		return r;

	*data = msr.data;
	return 0;
}

static int do_set_msr(struct kvm_vcpu *vcpu, unsigned index, u64 *data)
{
	struct msr_data msr;

	msr.data = *data;
	msr.index = index;
	msr.host_initiated = true;
	return kvm_set_msr(vcpu, &msr);
}

void kvm_set_pending_timer(struct kvm_vcpu *vcpu)
{
	/*
	 * Note: GVM_REQ_PENDING_TIMER is implicitly checked in
	 * vcpu_enter_guest.  This function is only called from
	 * the physical CPU that is running vcpu.
	 */
	kvm_make_request(GVM_REQ_PENDING_TIMER, vcpu);
}

#ifdef CONFIG_X86_64
static atomic_t kvm_guest_has_master_clock = ATOMIC_INIT(0);
#endif

static DEFINE_PER_CPU(size_t, cpu_tsc_khz);
static size_t max_tsc_khz;

static void update_ia32_tsc_adjust_msr(struct kvm_vcpu *vcpu, s64 offset)
{
	u64 curr_offset = vcpu->arch.tsc_offset;
	vcpu->arch.ia32_tsc_adjust_msr += offset - curr_offset;
}

static u64 kvm_compute_tsc_offset(struct kvm_vcpu *vcpu, u64 target_tsc)
{
	u64 tsc;

	tsc = __rdtsc();

	return target_tsc - tsc;
}

u64 kvm_read_l1_tsc(struct kvm_vcpu *vcpu, u64 host_tsc)
{
	return vcpu->arch.tsc_offset + host_tsc;
}

static void kvm_vcpu_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	kvm_x86_ops->write_tsc_offset(vcpu, offset);
	vcpu->arch.tsc_offset = offset;
}

void kvm_write_tsc(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	u64 offset;
	//size_t flags;
	u64 data = msr->data;

	//spin_lock_irqsave(&kvm->arch.tsc_write_lock, flags);
	offset = kvm_compute_tsc_offset(vcpu, data);
	if (guest_cpuid_has_tsc_adjust(vcpu) && !msr->host_initiated)
		update_ia32_tsc_adjust_msr(vcpu, offset);
	kvm_vcpu_write_tsc_offset(vcpu, offset);
	//spin_unlock_irqrestore(&kvm->arch.tsc_write_lock, flags);

}


static inline void adjust_tsc_offset_guest(struct kvm_vcpu *vcpu,
					   s64 adjustment)
{
	kvm_vcpu_write_tsc_offset(vcpu, vcpu->arch.tsc_offset + adjustment);
}

int kvm_set_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	//bool pr = false;
	u32 msr = msr_info->index;
	u64 data = msr_info->data;

	if (msr >= 0x200 && msr <= 0x2ff)
		return kvm_mtrr_set_msr(vcpu, msr, data);
	if (msr >= APIC_BASE_MSR && msr <= (APIC_BASE_MSR + 0x3ff))
		return kvm_x2apic_msr_write(vcpu, msr, data);
	switch (msr) {
	case MSR_AMD64_NB_CFG:
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case MSR_VM_HSAVE_PA:
	case MSR_AMD64_PATCH_LOADER:
	case MSR_AMD64_BU_CFG2:
		break;

	case MSR_EFER:
		return set_efer(vcpu, data);
	case MSR_K7_HWCR:
		data &= ~(u64)0x40;	/* ignore flush filter disable */
		data &= ~(u64)0x100;	/* ignore ignne emulation enable */
		data &= ~(u64)0x8;	/* ignore TLB cache disable */
		data &= ~(u64)0x40000;  /* ignore Mc status write enable */
		if (data != 0) {
			vcpu_unimpl(vcpu, "unimplemented HWCR wrmsr: 0x%llx\n",
				    data);
			return 1;
		}
		break;
	case MSR_FAM10H_MMIO_CONF_BASE:
		if (data != 0) {
			vcpu_unimpl(vcpu, "unimplemented MMIO_CONF_BASE wrmsr: "
				    "0x%llx\n", data);
			return 1;
		}
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!data) {
			/* We support the non-activated case already */
			break;
		} else if (data & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF)) {
			/* Values other than LBR and BTF are vendor-specific,
			   thus reserved and should throw a #GP */
			return 1;
		}
		vcpu_unimpl(vcpu, "%s: MSR_IA32_DEBUGCTLMSR 0x%llx, nop\n",
			    __func__, data);
		break;
	case MSR_IA32_APICBASE:
		return kvm_set_apic_base(vcpu, msr_info);
	case MSR_IA32_TSC_ADJUST:
		if (guest_cpuid_has_tsc_adjust(vcpu)) {
			if (!msr_info->host_initiated) {
				s64 adj = data - vcpu->arch.ia32_tsc_adjust_msr;
				adjust_tsc_offset_guest(vcpu, adj);
			}
			vcpu->arch.ia32_tsc_adjust_msr = data;
		}
		break;
	case MSR_IA32_MISC_ENABLE:
		vcpu->arch.ia32_misc_enable_msr = data;
		break;
	case MSR_IA32_SMBASE:
		if (!msr_info->host_initiated)
			return 1;
		vcpu->arch.smbase = data;
		break;
#if 0
	case MSR_K7_PERFCTR0 ... MSR_K7_PERFCTR3:
	case MSR_P6_PERFCTR0 ... MSR_P6_PERFCTR1:
		pr = true; /* fall through */
	case MSR_K7_EVNTSEL0 ... MSR_K7_EVNTSEL3:
	case MSR_P6_EVNTSEL0 ... MSR_P6_EVNTSEL1:
		if (kvm_pmu_is_valid_msr(vcpu, msr))
			return kvm_pmu_set_msr(vcpu, msr_info);

		if (pr || data != 0)
			vcpu_unimpl(vcpu, "disabled perfctr wrmsr: "
				    "0x%x data 0x%llx\n", msr, data);
		break;
#endif
	case MSR_K7_CLK_CTL:
		/*
		 * Ignore all writes to this no longer documented MSR.
		 * Writes are only relevant for old K7 processors,
		 * all pre-dating SVM, but a recommended workaround from
		 * AMD for these chips. It is possible to specify the
		 * affected processor models on the command line, hence
		 * the need to ignore the workaround.
		 */
		break;
#if 0
	case MSR_IA32_BBL_CR_CTL3:
		/* Drop writes to this legacy MSR -- see rdmsr
		 * counterpart for further detail.
		 */
		vcpu_unimpl(vcpu, "ignored wrmsr: 0x%x data 0x%llx\n", msr, data);
		break;
#endif
	case MSR_AMD64_OSVW_ID_LENGTH:
		if (!guest_cpuid_has_osvw(vcpu))
			return 1;
		vcpu->arch.osvw.length = data;
		break;
	case MSR_AMD64_OSVW_STATUS:
		if (!guest_cpuid_has_osvw(vcpu))
			return 1;
		vcpu->arch.osvw.status = data;
		break;
	default:
#if 0
		if (kvm_pmu_is_valid_msr(vcpu, msr))
			return kvm_pmu_set_msr(vcpu, msr_info);
		if (!ignore_msrs) {
			vcpu_unimpl(vcpu, "unhandled wrmsr: 0x%x data 0x%llx\n",
				    msr, data);
			return 1;
		} else {
			vcpu_unimpl(vcpu, "ignored wrmsr: 0x%x data 0x%llx\n",
				    msr, data);
			break;
		}
#endif
		break;
	}
	return 0;
}


/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	return kvm_x86_ops->get_msr(vcpu, msr);
}

int kvm_get_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (msr_info->index >= 0x200 && msr_info->index <= 0x2ff)
		return kvm_mtrr_get_msr(vcpu, msr_info->index, &msr_info->data);
	if (msr_info->index >= APIC_BASE_MSR && msr_info->index <= (APIC_BASE_MSR + 0x3ff))
		return kvm_x2apic_msr_read(vcpu, msr_info->index, &msr_info->data);
	switch (msr_info->index) {
	case MSR_IA32_PLATFORM_ID:
	case MSR_IA32_EBL_CR_POWERON:
	case MSR_IA32_DEBUGCTLMSR:
	case MSR_IA32_LASTBRANCHFROMIP:
	case MSR_IA32_LASTBRANCHTOIP:
	case MSR_IA32_LASTINTFROMIP:
	case MSR_IA32_LASTINTTOIP:
	case MSR_K8_SYSCFG:
	case MSR_K8_TSEG_ADDR:
	case MSR_K8_TSEG_MASK:
	case MSR_K7_HWCR:
	case MSR_VM_HSAVE_PA:
	case MSR_K8_INT_PENDING_MSG:
	case MSR_AMD64_NB_CFG:
	case MSR_FAM10H_MMIO_CONF_BASE:
	case MSR_AMD64_BU_CFG2:
	case MSR_IA32_PERF_CTL:
		msr_info->data = 0;
		break;
#if 0
	case MSR_K7_EVNTSEL0 ... MSR_K7_EVNTSEL3:
	case MSR_K7_PERFCTR0 ... MSR_K7_PERFCTR3:
	case MSR_P6_PERFCTR0 ... MSR_P6_PERFCTR1:
	case MSR_P6_EVNTSEL0 ... MSR_P6_EVNTSEL1:
		if (kvm_pmu_is_valid_msr(vcpu, msr_info->index))
			return kvm_pmu_get_msr(vcpu, msr_info->index, &msr_info->data);
		msr_info->data = 0;
		break;
#endif
	case MSR_IA32_UCODE_REV:
		msr_info->data = 0x100000000ULL;
		break;
	case MSR_MTRRcap:
		return kvm_mtrr_get_msr(vcpu, msr_info->index, &msr_info->data);
	case 0xcd: /* fsb frequency */
		msr_info->data = 3;
		break;
		/*
		 * MSR_EBC_FREQUENCY_ID
		 * Conservative value valid for even the basic CPU models.
		 * Models 0,1: 000 in bits 23:21 indicating a bus speed of
		 * 100MHz, model 2 000 in bits 18:16 indicating 100MHz,
		 * and 266MHz for model 3, or 4. Set Core Clock
		 * Frequency to System Bus Frequency Ratio to 1 (bits
		 * 31:24) even though these are only valid for CPU
		 * models > 2, however guests may end up dividing or
		 * multiplying by zero otherwise.
		 */
	case MSR_EBC_FREQUENCY_ID:
		msr_info->data = 1 << 24;
		break;
	case MSR_IA32_APICBASE:
		msr_info->data = kvm_get_apic_base(vcpu);
		break;
	case MSR_IA32_TSC_ADJUST:
		msr_info->data = (u64)vcpu->arch.ia32_tsc_adjust_msr;
		break;
	case MSR_IA32_MISC_ENABLE:
		msr_info->data = vcpu->arch.ia32_misc_enable_msr;
		break;
	case MSR_IA32_SMBASE:
		if (!msr_info->host_initiated)
			return 1;
		msr_info->data = vcpu->arch.smbase;
		break;
	case MSR_IA32_PERF_STATUS:
		/* TSC increment by tick */
		msr_info->data = 1000ULL;
		/* CPU multiplier */
		msr_info->data |= (((uint64_t)4ULL) << 40);
		break;
	case MSR_EFER:
		msr_info->data = vcpu->arch.efer;
		break;
#if 0
	case MSR_K7_CLK_CTL:
		/*
		 * Provide expected ramp-up count for K7. All other
		 * are set to zero, indicating minimum divisors for
		 * every field.
		 *
		 * This prevents guest kernels on AMD host with CPU
		 * type 6, model 8 and higher from exploding due to
		 * the rdmsr failing.
		 */
		msr_info->data = 0x20000000;
		break;
#endif
	case MSR_IA32_BBL_CR_CTL3:
		/* This legacy MSR exists but isn't fully documented in current
		 * silicon.  It is however accessed by winxp in very narrow
		 * scenarios where it sets bit #19, itself documented as
		 * a "reserved" bit.  Best effort attempt to source coherent
		 * read data here should the balance of the register be
		 * interpreted by the guest:
		 *
		 * L2 cache control register 3: 64GB range, 256KB size,
		 * enabled, latency 0x1, configured
		 */
		msr_info->data = 0xbe702111;
		break;
	case MSR_AMD64_OSVW_ID_LENGTH:
		if (!guest_cpuid_has_osvw(vcpu))
			return 1;
		msr_info->data = vcpu->arch.osvw.length;
		break;
	case MSR_AMD64_OSVW_STATUS:
		if (!guest_cpuid_has_osvw(vcpu))
			return 1;
		msr_info->data = vcpu->arch.osvw.status;
		break;
	default:
#if 0
		if (kvm_pmu_is_valid_msr(vcpu, msr_info->index))
			return kvm_pmu_get_msr(vcpu, msr_info->index, &msr_info->data);
		if (!ignore_msrs) {
			vcpu_unimpl(vcpu, "unhandled rdmsr: 0x%x\n", msr_info->index);
			return 1;
		} else {
			vcpu_unimpl(vcpu, "ignored rdmsr: 0x%x\n", msr_info->index);
			msr_info->data = 0;
		}
		break;
#endif
		break;
	}
	return 0;
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int __msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
		    struct kvm_msr_entry *entries,
		    int (*do_msr)(struct kvm_vcpu *vcpu,
				  unsigned index, u64 *data))
{
	int i, idx;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	for (i = 0; i < msrs->nmsrs; ++i)
		if (do_msr(vcpu, entries[i].index, &entries[i].data))
			break;
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	return i;
}

/*
 * Read or write a bunch of msrs. Parameters are user addresses.
 *
 * @return number of msrs set successfully.
 */
static int msr_io(PIRP pIrp, struct kvm_vcpu *vcpu,
	          struct kvm_msrs __user *user_msrs,
		  int (*do_msr)(struct kvm_vcpu *vcpu,
				unsigned index, u64 *data),
		  int writeback)
{
	struct kvm_msrs msrs;
	struct kvm_msr_entry *entries;
	int r, n;
	unsigned size;

	r = -EFAULT;
	if (copy_from_user(&msrs, user_msrs, sizeof msrs))
		goto out;

	r = -E2BIG;
	if (msrs.nmsrs >= MAX_IO_MSRS)
		goto out;

	size = sizeof(struct kvm_msr_entry) * msrs.nmsrs;
	entries = memdup_user(user_msrs->entries, size);
	if (IS_ERR(entries)) {
		r = PTR_ERR(entries);
		goto out;
	}

	r = n = __msr_io(vcpu, &msrs, entries, do_msr);
	if (r < 0)
		goto out_free;

	/* write back n of msrs handled here*/
	r = gvmUpdateReturnBuffer(pIrp, 0, &n, sizeof(n));
	if (r)
		goto out_free;

	if (writeback) {
		r = gvmUpdateReturnBuffer(pIrp, sizeof(msrs), entries, size);
		if (r)
			goto out_free;
	}

	r = n;

out_free:
	kfree(entries);
out:
	return r;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case GVM_CAP_IRQCHIP:
	case GVM_CAP_HLT:
	case GVM_CAP_MMU_SHADOW_CACHE_CONTROL:
	case GVM_CAP_EXT_EMUL_CPUID:
	case GVM_CAP_NOP_IO_DELAY:
	case GVM_CAP_SYNC_MMU:
	case GVM_CAP_USER_NMI:
	case GVM_CAP_REINJECT_CONTROL:
	case GVM_CAP_SET_IDENTITY_MAP_ADDR:
	case GVM_CAP_VCPU_EVENTS:
		r = 1;
		break;
	case GVM_CAP_PCI_SEGMENT:
	case GVM_CAP_DEBUGREGS:
	case GVM_CAP_X86_ROBUST_SINGLESTEP:
	case GVM_CAP_XSAVE:
	case GVM_CAP_READONLY_MEM:
	case GVM_CAP_IOAPIC_POLARITY_IGNORED:
	case GVM_CAP_ENABLE_CAP_VM:
	case GVM_CAP_DISABLE_QUIRKS:
	case GVM_CAP_SET_BOOT_CPU_ID:
		r = 0;
		break;
	case GVM_CAP_X86_SMM:
		/* SMBASE is usually relocated above 1M on modern chipsets,
		 * and SMM handlers might indeed rely on 4G segment limits,
		 * so do not report SMM to be available if real mode is
		 * emulated via vm86 mode.  Still, do not go to great lengths
		 * to avoid userspace's usage of the feature, because it is a
		 * fringe case that is not enabled except via specific settings
		 * of the module parameters.
		 */
		r = kvm_x86_ops->cpu_has_high_real_mode_segbase();
		break;
	case GVM_CAP_VAPIC:
		r = !kvm_x86_ops->cpu_has_accelerated_tpr();
		break;
	case GVM_CAP_NR_VCPUS:
		r = GVM_SOFT_MAX_VCPUS;
		break;
	case GVM_CAP_MAX_VCPUS:
		r = GVM_MAX_VCPUS;
		break;
	case GVM_CAP_NR_MEMSLOTS:
		r = GVM_USER_MEM_SLOTS;
		break;
	case GVM_CAP_XCRS:
		r = boot_cpu_has(X86_FEATURE_XSAVE);
		break;
	default:
		r = 0;
		break;
	}
	return r;

}

long kvm_arch_dev_ioctl(struct gvm_device_extension *devext,
			PIRP pIrp, unsigned int ioctl)
{
	void __user *argp = (void __user *)pIrp->AssociatedIrp.SystemBuffer;
	size_t args = IoGetCurrentIrpStackLocation(pIrp)->Parameters.DeviceIoControl.InputBufferLength;
	long r;

	switch (ioctl) {
	case GVM_GET_MSR_INDEX_LIST: {
		struct kvm_msr_list *msr_list = argp;
		unsigned n;

		if (args < sizeof(struct kvm_msr_list)) {
			r = -EINVAL;
			goto out;
		}

		r = STATUS_SUCCESS;
		n = msr_list->nmsrs;
		__u32 nmsrs = num_msrs_to_save;
		r = gvmUpdateReturnBuffer(pIrp, 0, &nmsrs, sizeof(nmsrs));
		if (r)
			goto out;

		if (n < nmsrs) {
			r = -E2BIG;
			goto out;
		}

		r = gvmUpdateReturnBuffer(pIrp, sizeof(nmsrs), &msrs_to_save,
			num_msrs_to_save * sizeof(u32));
		break;
	}
	case GVM_GET_SUPPORTED_CPUID:
	case GVM_GET_EMULATED_CPUID: {
		struct kvm_cpuid __user *cpuid_arg = argp;
		struct kvm_cpuid cpuid;

		r = -EFAULT;
		if (copy_from_user(&cpuid, cpuid_arg, sizeof cpuid))
			goto out;

		r = kvm_dev_ioctl_get_cpuid(pIrp, &cpuid, cpuid_arg->entries,
					    ioctl);
		if (r)
			goto out;

		r = 0;
		break;
	}
	default:
		r = -EINVAL;
	}
out:
	return r;
}

static int kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	return kvm_apic_get_state(vcpu, s);
}

static int kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	int r;

	r = kvm_apic_set_state(vcpu, s);
	if (r)
		return r;
	update_cr8_intercept(vcpu);

	return 0;
}

static int kvm_cpu_accept_dm_intr(struct kvm_vcpu *vcpu)
{
	return (!lapic_in_kernel(vcpu) ||
		kvm_apic_accept_pic_intr(vcpu));
}

/*
 * if userspace requested an interrupt window, check that the
 * interrupt window is open.
 *
 * No need to exit to userspace if we already have an interrupt queued.
 */
static int kvm_vcpu_ready_for_interrupt_injection(struct kvm_vcpu *vcpu)
{
	return kvm_arch_interrupt_allowed(vcpu) &&
		!kvm_cpu_has_interrupt(vcpu) &&
		!kvm_event_needs_reinjection(vcpu) &&
		kvm_cpu_accept_dm_intr(vcpu);
}

static int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
				    struct kvm_interrupt *irq)
{
	if (irq->irq >= GVM_NR_INTERRUPTS)
		return -EINVAL;

	if (!irqchip_in_kernel(vcpu->kvm)) {
		kvm_queue_interrupt(vcpu, irq->irq, false);
		kvm_make_request(GVM_REQ_EVENT, vcpu);
		return 0;
	}

	/*
	 * With in-kernel LAPIC, we only use this to inject EXTINT, so
	 * fail for in-kernel 8259.
	 */
	if (pic_in_kernel(vcpu->kvm))
		return -ENXIO;

	if (vcpu->arch.pending_external_vector != -1)
		return -EEXIST;

	vcpu->arch.pending_external_vector = irq->irq;
	kvm_make_request(GVM_REQ_EVENT, vcpu);
	return 0;
}

static int kvm_vcpu_ioctl_nmi(struct kvm_vcpu *vcpu)
{
	kvm_inject_nmi(vcpu);

	return 0;
}

static int kvm_vcpu_ioctl_smi(struct kvm_vcpu *vcpu)
{
	kvm_make_request(GVM_REQ_SMI, vcpu);

	return 0;
}

static int vcpu_ioctl_tpr_access_reporting(struct kvm_vcpu *vcpu,
					   struct kvm_tpr_access_ctl *tac)
{
	if (tac->flags)
		return -EINVAL;
	vcpu->arch.tpr_access_reporting = !!tac->enabled;
	return 0;
}

static void kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_events *events)
{
	process_nmi(vcpu);
	events->exception.injected =
		vcpu->arch.exception.pending &&
		!kvm_exception_is_soft(vcpu->arch.exception.nr);
	events->exception.nr = vcpu->arch.exception.nr;
	events->exception.has_error_code = vcpu->arch.exception.has_error_code;
	events->exception.pad = 0;
	events->exception.error_code = vcpu->arch.exception.error_code;

	events->interrupt.injected =
		vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft;
	events->interrupt.nr = vcpu->arch.interrupt.nr;
	events->interrupt.soft = 0;
	events->interrupt.shadow = kvm_x86_ops->get_interrupt_shadow(vcpu);

	events->nmi.injected = vcpu->arch.nmi_injected;
	events->nmi.pending = vcpu->arch.nmi_pending != 0;
	events->nmi.masked = kvm_x86_ops->get_nmi_mask(vcpu);
	events->nmi.pad = 0;

	events->sipi_vector = 0; /* never valid when reporting to user space */

	events->smi.smm = is_smm(vcpu);
	events->smi.pending = vcpu->arch.smi_pending;
	events->smi.smm_inside_nmi =
		!!(vcpu->arch.hflags & HF_SMM_INSIDE_NMI_MASK);
	events->smi.latched_init = kvm_lapic_latched_init(vcpu);

	events->flags = (GVM_VCPUEVENT_VALID_NMI_PENDING
			 | GVM_VCPUEVENT_VALID_SHADOW
			 | GVM_VCPUEVENT_VALID_SMM);
	memset(&events->reserved, 0, sizeof(events->reserved));
}

static int kvm_vcpu_ioctl_x86_set_vcpu_events(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_events *events)
{
	if (events->flags & ~(GVM_VCPUEVENT_VALID_NMI_PENDING
			      | GVM_VCPUEVENT_VALID_SIPI_VECTOR
			      | GVM_VCPUEVENT_VALID_SHADOW
			      | GVM_VCPUEVENT_VALID_SMM))
		return -EINVAL;

	if (events->exception.injected &&
	    (events->exception.nr > 31 || events->exception.nr == NMI_VECTOR))
		return -EINVAL;

	process_nmi(vcpu);
	vcpu->arch.exception.pending = events->exception.injected;
	vcpu->arch.exception.nr = events->exception.nr;
	vcpu->arch.exception.has_error_code = events->exception.has_error_code;
	vcpu->arch.exception.error_code = events->exception.error_code;

	vcpu->arch.interrupt.pending = events->interrupt.injected;
	vcpu->arch.interrupt.nr = events->interrupt.nr;
	vcpu->arch.interrupt.soft = events->interrupt.soft;
	if (events->flags & GVM_VCPUEVENT_VALID_SHADOW)
		kvm_x86_ops->set_interrupt_shadow(vcpu,
						  events->interrupt.shadow);

	vcpu->arch.nmi_injected = events->nmi.injected;
	if (events->flags & GVM_VCPUEVENT_VALID_NMI_PENDING)
		vcpu->arch.nmi_pending = events->nmi.pending;
	kvm_x86_ops->set_nmi_mask(vcpu, events->nmi.masked);

	if (events->flags & GVM_VCPUEVENT_VALID_SIPI_VECTOR &&
	    lapic_in_kernel(vcpu))
		vcpu->arch.apic->sipi_vector = events->sipi_vector;

	if (events->flags & GVM_VCPUEVENT_VALID_SMM) {
		if (events->smi.smm)
			vcpu->arch.hflags |= HF_SMM_MASK;
		else
			vcpu->arch.hflags &= ~HF_SMM_MASK;
		vcpu->arch.smi_pending = events->smi.pending;
		if (events->smi.smm_inside_nmi)
			vcpu->arch.hflags |= HF_SMM_INSIDE_NMI_MASK;
		else
			vcpu->arch.hflags &= ~HF_SMM_INSIDE_NMI_MASK;
		if (lapic_in_kernel(vcpu)) {
			if (events->smi.latched_init)
				set_bit(GVM_APIC_INIT, &vcpu->arch.apic->pending_events);
			else
				clear_bit(GVM_APIC_INIT, &vcpu->arch.apic->pending_events);
		}
	}

	kvm_make_request(GVM_REQ_EVENT, vcpu);

	return 0;
}

static void kvm_vcpu_ioctl_x86_get_debugregs(struct kvm_vcpu *vcpu,
					     struct kvm_debugregs *dbgregs)
{
	size_t val;

	memcpy(dbgregs->db, vcpu->arch.db, sizeof(vcpu->arch.db));
	kvm_get_dr(vcpu, 6, &val);
	dbgregs->dr6 = val;
	dbgregs->dr7 = vcpu->arch.dr7;
	dbgregs->flags = 0;
	memset(&dbgregs->reserved, 0, sizeof(dbgregs->reserved));
}

static int kvm_vcpu_ioctl_x86_set_debugregs(struct kvm_vcpu *vcpu,
					    struct kvm_debugregs *dbgregs)
{
	if (dbgregs->flags)
		return -EINVAL;

	if (dbgregs->dr6 & ~0xffffffffull)
		return -EINVAL;
	if (dbgregs->dr7 & ~0xffffffffull)
		return -EINVAL;

	memcpy(vcpu->arch.db, dbgregs->db, sizeof(vcpu->arch.db));
	kvm_update_dr0123(vcpu);
	vcpu->arch.dr6 = dbgregs->dr6;
	kvm_update_dr6(vcpu);
	vcpu->arch.dr7 = dbgregs->dr7;
	kvm_update_dr7(vcpu);

	return 0;
}

u64 xfeatures_mask;
static unsigned int xstate_offsets[XFEATURE_MAX] = { 0 };
static unsigned int xstate_sizes[XFEATURE_MAX]   = { 0 };
static unsigned int xstate_comp_offsets[sizeof(xfeatures_mask)*8];

/*
 * Note that in the future we will likely need a pair of
 * functions here: one for user xstates and the other for
 * system xstates.  For now, they are the same.
 */
static int xfeature_enabled(enum xfeature xfeature)
{
	return !!(xfeatures_mask & ((u64)1 << xfeature));
}

/*
 * Given an xstate feature mask, calculate where in the xsave
 * buffer the state is.  Callers should ensure that the buffer
 * is valid.
 *
 * Note: does not work for compacted buffers.
 */
static void *__raw_xsave_addr(struct xregs_state *xsave, int xstate_feature_mask)
{
	int feature_nr = fls64(xstate_feature_mask) - 1;

	if (!xfeature_enabled(feature_nr)) {
		return NULL;
	}

	return (u8 *)xsave + xstate_comp_offsets[feature_nr];
}

/*
 * Given the xsave area and a state inside, this function returns the
 * address of the state.
 *
 * This is the API that is called to get xstate address in either
 * standard format or compacted format of xsave area.
 *
 * Note that if there is no data for the field in the xsave buffer
 * this will return NULL.
 *
 * Inputs:
 *	xstate: the thread's storage area for all FPU data
 *	xstate_feature: state which is defined in xsave.h (e.g.
 *	XFEATURE_MASK_FP, XFEATURE_MASK_SSE, etc...)
 * Output:
 *	address of the state in the xsave area, or NULL if the
 *	field is not present in the xsave buffer.
 */
void *get_xsave_addr(struct xregs_state *xsave, int xstate_feature)
{
	/*
	 * Do we even *have* xsave state?
	 */
	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return NULL;

	/*
	 * This assumes the last 'xsave*' instruction to
	 * have requested that 'xstate_feature' be saved.
	 * If it did not, we might be seeing and old value
	 * of the field in the buffer.
	 *
	 * This can happen because the last 'xsave' did not
	 * request that this feature be saved (unlikely)
	 * or because the "init optimization" caused it
	 * to not be saved.
	 */
	if (!(xsave->header.xfeatures & xstate_feature))
		return NULL;

	return __raw_xsave_addr(xsave, xstate_feature);
}

#define XSTATE_COMPACTION_ENABLED (1ULL << 63)

static void fill_xsave(u8 *dest, struct kvm_vcpu *vcpu)
{
	struct xregs_state *xsave = &vcpu->arch.guest_fpu.xsave;
	u64 xstate_bv = xsave->header.xfeatures;
	u64 valid;

	/*
	 * Copy legacy XSAVE area, to avoid complications with CPUID
	 * leaves 0 and 1 in the loop below.
	 */
	memcpy(dest, xsave, XSAVE_HDR_OFFSET);

	/* Set XSTATE_BV */
	*(u64 *)(dest + XSAVE_HDR_OFFSET) = xstate_bv;

	/*
	 * Copy each region from the possibly compacted offset to the
	 * non-compacted offset.
	 */
	valid = xstate_bv & ~XFEATURE_MASK_FPSSE;
	while (valid) {
		u64 feature = valid & -(s64)valid;
		int index = fls64(feature) - 1;
		void *src = get_xsave_addr(xsave, feature);

		if (src) {
			u32 size, offset, ecx, edx;
			cpuid_count(XSTATE_CPUID, index,
				    &size, &offset, &ecx, &edx);
			memcpy(dest + offset, src, size);
		}

		valid -= feature;
	}
}

static void load_xsave(struct kvm_vcpu *vcpu, u8 *src)
{
	struct xregs_state *xsave = &vcpu->arch.guest_fpu.xsave;
	u64 xstate_bv = *(u64 *)(src + XSAVE_HDR_OFFSET);
	u64 valid;

	/*
	 * Copy legacy XSAVE area, to avoid complications with CPUID
	 * leaves 0 and 1 in the loop below.
	 */
	memcpy(xsave, src, XSAVE_HDR_OFFSET);

	/* Set XSTATE_BV and possibly XCOMP_BV.  */
	xsave->header.xfeatures = xstate_bv;
	if (boot_cpu_has(X86_FEATURE_XSAVES))
		xsave->header.xcomp_bv = host_xcr0 | XSTATE_COMPACTION_ENABLED;

	/*
	 * Copy each region from the non-compacted offset to the
	 * possibly compacted offset.
	 */
	valid = xstate_bv & ~XFEATURE_MASK_FPSSE;
	while (valid) {
		u64 feature = valid & -(s64)valid;
		int index = fls64(feature) - 1;
		void *dest = get_xsave_addr(xsave, feature);

		if (dest) {
			u32 size, offset, ecx, edx;
			cpuid_count(XSTATE_CPUID, index,
				    &size, &offset, &ecx, &edx);
			memcpy(dest, src + offset, size);
		}

		valid -= feature;
	}
}

static void kvm_vcpu_ioctl_x86_get_xsave(struct kvm_vcpu *vcpu,
					 struct kvm_xsave *guest_xsave)
{
	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		memset(guest_xsave, 0, sizeof(struct kvm_xsave));
		fill_xsave((u8 *) guest_xsave->region, vcpu);
	} else {
		memcpy(guest_xsave->region,
			&vcpu->arch.guest_fpu.fxsave,
			sizeof(struct fxregs_state));
		*(u64 *)&guest_xsave->region[XSAVE_HDR_OFFSET / sizeof(u32)] =
			XFEATURE_MASK_FPSSE;
	}
}

static int kvm_vcpu_ioctl_x86_set_xsave(struct kvm_vcpu *vcpu,
					struct kvm_xsave *guest_xsave)
{
	u64 xstate_bv =
		*(u64 *)&guest_xsave->region[XSAVE_HDR_OFFSET / sizeof(u32)];

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		/*
		 * Here we allow setting states that are not present in
		 * CPUID leaf 0xD, index 0, EDX:EAX.  This is for compatibility
		 * with old userspace.
		 */
		if (xstate_bv & ~kvm_supported_xcr0())
			return -EINVAL;
		load_xsave(vcpu, (u8 *)guest_xsave->region);
	} else {
		if (xstate_bv & ~XFEATURE_MASK_FPSSE)
			return -EINVAL;
		memcpy(&vcpu->arch.guest_fpu.fxsave,
			guest_xsave->region, sizeof(struct fxregs_state));
	}
	return 0;
}

static void kvm_vcpu_ioctl_x86_get_xcrs(struct kvm_vcpu *vcpu,
					struct kvm_xcrs *guest_xcrs)
{
	if (!boot_cpu_has(X86_FEATURE_XSAVE)) {
		guest_xcrs->nr_xcrs = 0;
		return;
	}

	guest_xcrs->nr_xcrs = 1;
	guest_xcrs->flags = 0;
	guest_xcrs->xcrs[0].xcr = XCR_XFEATURE_ENABLED_MASK;
	guest_xcrs->xcrs[0].value = vcpu->arch.xcr0;
}

static int kvm_vcpu_ioctl_x86_set_xcrs(struct kvm_vcpu *vcpu,
				       struct kvm_xcrs *guest_xcrs)
{
	int i, r = 0;

	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return -EINVAL;

	if (guest_xcrs->nr_xcrs > GVM_MAX_XCRS || guest_xcrs->flags)
		return -EINVAL;

	for (i = 0; i < guest_xcrs->nr_xcrs; i++)
		/* Only support XCR0 currently */
		if (guest_xcrs->xcrs[i].xcr == XCR_XFEATURE_ENABLED_MASK) {
			r = __kvm_set_xcr(vcpu, XCR_XFEATURE_ENABLED_MASK,
				guest_xcrs->xcrs[i].value);
			break;
		}
	if (r)
		r = -EINVAL;
	return r;
}

long kvm_arch_vcpu_ioctl(struct gvm_device_extension *devext,
			 PIRP pIrp, unsigned int ioctl)
{
	struct kvm_vcpu *vcpu = devext->PrivData;
	void __user *argp = (void __user *)pIrp->AssociatedIrp.SystemBuffer;
	int r;
	union {
		struct kvm_lapic_state *lapic;
		struct kvm_xsave *xsave;
		struct kvm_xcrs *xcrs;
		void *buffer;
	} u;

	u.buffer = NULL;
	switch (ioctl) {
	case GVM_GET_LAPIC: {
		r = -EINVAL;
		if (!lapic_in_kernel(vcpu))
			goto out;
		u.lapic = kzalloc(sizeof(struct kvm_lapic_state), GFP_KERNEL);

		r = -ENOMEM;
		if (!u.lapic)
			goto out;
		r = kvm_vcpu_ioctl_get_lapic(vcpu, u.lapic);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, u.lapic,
			       sizeof(struct kvm_lapic_state));
		break;
	}
	case GVM_SET_LAPIC: {
		r = -EINVAL;
		if (!lapic_in_kernel(vcpu))
			goto out;
		u.lapic = memdup_user(argp, sizeof(*u.lapic));
		if (IS_ERR(u.lapic))
			return PTR_ERR(u.lapic);

		r = kvm_vcpu_ioctl_set_lapic(vcpu, u.lapic);
		break;
	}
	case GVM_INTERRUPT: {
		struct kvm_interrupt irq;

		r = -EFAULT;
		if (copy_from_user(&irq, argp, sizeof irq))
			goto out;
		r = kvm_vcpu_ioctl_interrupt(vcpu, &irq);
		break;
	}
	case GVM_NMI: {
		r = kvm_vcpu_ioctl_nmi(vcpu);
		break;
	}
	case GVM_SMI: {
		r = kvm_vcpu_ioctl_smi(vcpu);
		break;
	}
	case GVM_SET_CPUID: {
		struct kvm_cpuid __user *cpuid_arg = argp;
		struct kvm_cpuid cpuid;

		r = -EFAULT;
		if (copy_from_user(&cpuid, cpuid_arg, sizeof cpuid))
			goto out;
		r = kvm_vcpu_ioctl_set_cpuid(vcpu, &cpuid,
					      cpuid_arg->entries);
		break;
	}
	case GVM_GET_CPUID: {
		struct kvm_cpuid __user *cpuid_arg = argp;
		struct kvm_cpuid cpuid;

		r = -EFAULT;
		if (copy_from_user(&cpuid, cpuid_arg, sizeof cpuid))
			goto out;
		r = kvm_vcpu_ioctl_get_cpuid(vcpu, &cpuid,
					      cpuid_arg->entries);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, &cpuid, sizeof(cpuid));
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, sizeof(cpuid), &vcpu->arch.cpuid_entries,
			 vcpu->arch.cpuid_nent * sizeof(struct kvm_cpuid_entry));
		break;
	}
	case GVM_GET_MSRS:
		r = msr_io(pIrp, vcpu, argp, do_get_msr, 1);
		break;
	case GVM_SET_MSRS:
		r = msr_io(pIrp, vcpu, argp, do_set_msr, 0);
		break;
	case GVM_TPR_ACCESS_REPORTING: {
		struct kvm_tpr_access_ctl tac;

		r = -EFAULT;
		if (copy_from_user(&tac, argp, sizeof tac))
			goto out;
		r = vcpu_ioctl_tpr_access_reporting(vcpu, &tac);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, &tac, sizeof(tac));
		break;
	};
	case GVM_SET_VAPIC_ADDR: {
		struct kvm_vapic_addr va;
		int idx;

		r = -EINVAL;
		if (!lapic_in_kernel(vcpu))
			goto out;
		r = -EFAULT;
		if (copy_from_user(&va, argp, sizeof va))
			goto out;
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		r = kvm_lapic_set_vapic_addr(vcpu, va.vapic_addr);
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
		break;
	}
	case GVM_GET_VCPU_EVENTS: {
		struct kvm_vcpu_events events;

		kvm_vcpu_ioctl_x86_get_vcpu_events(vcpu, &events);

		r = gvmUpdateReturnBuffer(pIrp, 0, &events,
			       sizeof(struct kvm_vcpu_events));
		break;
	}
	case GVM_SET_VCPU_EVENTS: {
		struct kvm_vcpu_events events;

		r = -EFAULT;
		if (copy_from_user(&events, argp, sizeof(struct kvm_vcpu_events)))
			break;

		r = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu, &events);
		break;
	}
	case GVM_GET_DEBUGREGS: {
		struct kvm_debugregs dbgregs;

		kvm_vcpu_ioctl_x86_get_debugregs(vcpu, &dbgregs);

		r = gvmUpdateReturnBuffer(pIrp, 0, &dbgregs,
			       sizeof(struct kvm_debugregs));
		break;
	}
	case GVM_SET_DEBUGREGS: {
		struct kvm_debugregs dbgregs;

		r = -EFAULT;
		if (copy_from_user(&dbgregs, argp,
				   sizeof(struct kvm_debugregs)))
			break;

		r = kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &dbgregs);
		break;
	}
	case GVM_GET_XSAVE: {
		u.xsave = kzalloc(sizeof(struct kvm_xsave), GFP_KERNEL);
		r = -ENOMEM;
		if (!u.xsave)
			break;

		kvm_vcpu_ioctl_x86_get_xsave(vcpu, u.xsave);

		r = gvmUpdateReturnBuffer(pIrp, 0, u.xsave,
			       sizeof(struct kvm_xsave));
		break;
	}
	case GVM_SET_XSAVE: {
		u.xsave = memdup_user(argp, sizeof(*u.xsave));
		if (IS_ERR(u.xsave))
			return PTR_ERR(u.xsave);

		r = kvm_vcpu_ioctl_x86_set_xsave(vcpu, u.xsave);
		break;
	}
	case GVM_GET_XCRS: {
		u.xcrs = kzalloc(sizeof(struct kvm_xcrs), GFP_KERNEL);
		r = -ENOMEM;
		if (!u.xcrs)
			break;

		kvm_vcpu_ioctl_x86_get_xcrs(vcpu, u.xcrs);

		r = gvmUpdateReturnBuffer(pIrp, 0, u.xcrs,
			       sizeof(struct kvm_xcrs));
		break;
	}
	case GVM_SET_XCRS: {
		u.xcrs = memdup_user(argp, sizeof(*u.xcrs));
		if (IS_ERR(u.xcrs))
			return PTR_ERR(u.xcrs);

		r = kvm_vcpu_ioctl_x86_set_xcrs(vcpu, u.xcrs);
		break;
	}
	default:
		r = -EINVAL;
	}
out:
	kfree(u.buffer);
	return r;
}

static int kvm_vm_ioctl_set_tss_addr(struct kvm *kvm, size_t addr)
{
	int ret;

	if (addr > (unsigned int)(-3 * PAGE_SIZE))
		return -EINVAL;
	ret = kvm_x86_ops->set_tss_addr(kvm, addr);
	return ret;
}

static int kvm_vm_ioctl_set_identity_map_addr(struct kvm *kvm,
					      u64 ident_addr)
{
	kvm->arch.ept_identity_map_addr = ident_addr;
	return 0;
}

static int kvm_vm_ioctl_set_nr_mmu_pages(struct kvm *kvm,
					  u32 kvm_nr_mmu_pages)
{
	if (kvm_nr_mmu_pages < GVM_MIN_ALLOC_MMU_PAGES)
		return -EINVAL;

	mutex_lock(&kvm->slots_lock);

	kvm_mmu_change_mmu_pages(kvm, kvm_nr_mmu_pages);
	kvm->arch.n_requested_mmu_pages = kvm_nr_mmu_pages;

	mutex_unlock(&kvm->slots_lock);
	return 0;
}

static int kvm_vm_ioctl_get_nr_mmu_pages(struct kvm *kvm)
{
	return kvm->arch.n_max_mmu_pages;
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case GVM_IRQCHIP_PIC_MASTER:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[0],
			sizeof(struct kvm_pic_state));
		break;
	case GVM_IRQCHIP_PIC_SLAVE:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[1],
			sizeof(struct kvm_pic_state));
		break;
	case GVM_IRQCHIP_IOAPIC:
		r = kvm_get_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case GVM_IRQCHIP_PIC_MASTER:
		spin_lock(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[0],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
		spin_unlock(&pic_irqchip(kvm)->lock);
		break;
	case GVM_IRQCHIP_PIC_SLAVE:
		spin_lock(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[1],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
		spin_unlock(&pic_irqchip(kvm)->lock);
		break;
	case GVM_IRQCHIP_IOAPIC:
		r = kvm_set_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = -EINVAL;
		break;
	}
	kvm_pic_update_irq(pic_irqchip(kvm));
	return r;
}

/**
 * kvm_vm_ioctl_get_dirty_log - get and clear the log of dirty pages in a slot
 * @kvm: kvm instance
 * @log: slot id and address to which we copy the log
 *
 * Steps 1-4 below provide general overview of dirty page logging. See
 * kvm_get_dirty_log_protect() function description for additional details.
 *
 * We call kvm_get_dirty_log_protect() to handle steps 1-3, upon return we
 * always flush the TLB (step 4) even if previous step failed  and the dirty
 * bitmap may be corrupt. Regardless of previous outcome the kvm logging API
 * does not preclude user space subsequent dirty log read. Flushing TLB ensures
 * writes will be marked dirty for next log read.
 *
 *   1. Take a snapshot of the bit and clear it if needed.
 *   2. Write protect the corresponding page.
 *   3. Copy the snapshot to the userspace.
 *   4. Flush TLB's if needed.
 */
int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	bool is_dirty = false;
	int r = 0;

	mutex_lock(&kvm->slots_lock);

	/*
	 * Flush potentially hardware-cached dirty pages to dirty_bitmap.
	 */
	if (kvm_x86_ops->flush_log_dirty)
		kvm_x86_ops->flush_log_dirty(kvm);

	r = kvm_get_dirty_log_protect(kvm, log, &is_dirty);

	/*
	 * All the TLBs can be flushed out of mmu lock, see the comments in
	 * kvm_mmu_slot_remove_write_access().
	 */
	if (is_dirty)
		kvm_flush_remote_tlbs(kvm);

	mutex_unlock(&kvm->slots_lock);
	return r;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_event,
			bool line_status)
{
	if (!irqchip_in_kernel(kvm))
		return -ENXIO;

	irq_event->status = kvm_set_irq(kvm, GVM_USERSPACE_IRQ_SOURCE_ID,
					irq_event->irq, irq_event->level,
					line_status);
	return 0;
}

static int kvm_vm_ioctl_enable_cap(struct kvm *kvm,
				   struct kvm_enable_cap *cap)
{
	int r;

	if (cap->flags)
		return -EINVAL;

	switch (cap->cap) {
	case GVM_CAP_DISABLE_QUIRKS:
		kvm->arch.disabled_quirks = cap->args[0];
		r = 0;
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

long kvm_arch_vm_ioctl(struct gvm_device_extension *devext,
		       PIRP pIrp, unsigned int ioctl)
{
	struct kvm *kvm = devext->PrivData;
	void __user *argp = (void __user *)pIrp->AssociatedIrp.SystemBuffer;
	int r = -ENOTTY;

	switch (ioctl) {
	case GVM_SET_TSS_ADDR:
		r = -EFAULT;
		if (IoGetCurrentIrpStackLocation(pIrp)->Parameters.DeviceIoControl.InputBufferLength
			< sizeof(size_t))
			goto out;
		r = kvm_vm_ioctl_set_tss_addr(kvm, *(size_t *)argp);
		break;
	case GVM_SET_IDENTITY_MAP_ADDR: {
		u64 ident_addr;

		r = -EFAULT;
		if (IoGetCurrentIrpStackLocation(pIrp)->Parameters.DeviceIoControl.InputBufferLength
			< sizeof(ident_addr))
			goto out;
		ident_addr = *(u64 *)argp;
		r = kvm_vm_ioctl_set_identity_map_addr(kvm, ident_addr);
		break;
	}
	case GVM_SET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_set_nr_mmu_pages(kvm, *(unsigned int*)argp);
		break;
	case GVM_GET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_get_nr_mmu_pages(kvm);
		break;
	case GVM_CREATE_IRQCHIP: {
		struct kvm_pic *vpic;

		mutex_lock(&kvm->lock);
		r = -EEXIST;
		if (kvm->arch.vpic)
			goto create_irqchip_unlock;
		r = -EINVAL;
		if (kvm->created_vcpus)
			goto create_irqchip_unlock;
		r = -ENOMEM;
		vpic = kvm_create_pic(kvm);
		if (vpic) {
			r = kvm_ioapic_init(kvm);
			if (r) {
				mutex_lock(&kvm->slots_lock);
				kvm_destroy_pic(vpic);
				mutex_unlock(&kvm->slots_lock);
				goto create_irqchip_unlock;
			}
		} else
			goto create_irqchip_unlock;
		r = kvm_setup_default_irq_routing(kvm);
		if (r) {
			mutex_lock(&kvm->slots_lock);
			mutex_lock(&kvm->irq_lock);
			kvm_ioapic_destroy(kvm);
			kvm_destroy_pic(vpic);
			mutex_unlock(&kvm->irq_lock);
			mutex_unlock(&kvm->slots_lock);
			goto create_irqchip_unlock;
		}
		/* Write kvm->irq_routing before kvm->arch.vpic.  */
		smp_wmb();
		kvm->arch.vpic = vpic;
	create_irqchip_unlock:
		mutex_unlock(&kvm->lock);
		break;
	}
	case GVM_GET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip *chip;

		chip = memdup_user(argp, sizeof(*chip));
		if (IS_ERR(chip)) {
			r = PTR_ERR(chip);
			goto out;
		}

		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto get_irqchip_out;
		r = kvm_vm_ioctl_get_irqchip(kvm, chip);
		if (r)
			goto get_irqchip_out;
		r = gvmUpdateReturnBuffer(pIrp, 0, chip, sizeof(*chip));
	get_irqchip_out:
		kfree(chip);
		break;
	}
	case GVM_SET_IRQCHIP: {
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */
		struct kvm_irqchip *chip;

		chip = memdup_user(argp, sizeof(*chip));
		if (IS_ERR(chip)) {
			r = PTR_ERR(chip);
			goto out;
		}

		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto set_irqchip_out;
		r = kvm_vm_ioctl_set_irqchip(kvm, chip);
		if (r)
			goto set_irqchip_out;
		r = 0;
	set_irqchip_out:
		kfree(chip);
		break;
	}
	case GVM_SET_BOOT_CPU_ID:
		r = 0;
		mutex_lock(&kvm->lock);
		if (kvm->created_vcpus)
			r = -EBUSY;
		else
			kvm->arch.bsp_vcpu_id = *(u32 *)argp;
		mutex_unlock(&kvm->lock);
		break;
	case GVM_ENABLE_CAP: {
		struct kvm_enable_cap cap;

		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			goto out;
		r = kvm_vm_ioctl_enable_cap(kvm, &cap);
		break;
	}
	default:
		break;
	}
out:
	return r;
}

static void kvm_init_msr_list(void)
{
	u32 dummy[2];
	unsigned i, j;

	for (i = j = 0; i < ARRAY_SIZE(msrs_to_save); i++) {
		if (rdmsr_safe(msrs_to_save[i], &dummy[0], &dummy[1]) < 0)
			continue;

		/*
		 * Even MSRs that are valid in the host may not be exposed
		 * to the guests in some cases.
		 */
		switch (msrs_to_save[i]) {
		case MSR_IA32_BNDCFGS:
			if (!kvm_x86_ops->mpx_supported())
				continue;
			break;
		case MSR_TSC_AUX:
			if (!kvm_x86_ops->rdtscp_supported())
				continue;
			break;
		default:
			break;
		}

		if (j < i)
			msrs_to_save[j] = msrs_to_save[i];
		j++;
	}
	num_msrs_to_save = j;

#if 0
	for (i = j = 0; i < ARRAY_SIZE(emulated_msrs); i++) {
		switch (emulated_msrs[i]) {
		case MSR_IA32_SMBASE:
			if (!kvm_x86_ops->cpu_has_high_real_mode_segbase())
				continue;
			break;
		default:
			break;
		}

		if (j < i)
			emulated_msrs[j] = emulated_msrs[i];
		j++;
	}
	num_emulated_msrs = j;
#endif
}

static int vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len,
			   const void *v)
{
	int handled = 0;
	int n;
	const char *__v = v;

	do {
		n = min(len, 8);
		if (!(lapic_in_kernel(vcpu) &&
		      !kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, addr, n, v))
		    && kvm_io_bus_write(vcpu, GVM_MMIO_BUS, addr, n, v))
			break;
		handled += n;
		addr += n;
		len -= n;
		__v = (char *)v;
		__v += n;
		v = (void *)__v;
	} while (len);

	return handled;
}

static int vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v)
{
	int handled = 0;
	int n;
	char *__v;

	do {
		n = min(len, 8);
		if (!(lapic_in_kernel(vcpu) &&
		      !kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev,
					 addr, n, v))
		    && kvm_io_bus_read(vcpu, GVM_MMIO_BUS, addr, n, v))
			break;
		handled += n;
		addr += n;
		len -= n;
		__v = (char *)v;
		__v += n;
		v = (void *)__v;
	} while (len);

	return handled;
}

static void kvm_set_segment(struct kvm_vcpu *vcpu,
			struct kvm_segment *var, int seg)
{
	kvm_x86_ops->set_segment(vcpu, var, seg);
}

void kvm_get_segment(struct kvm_vcpu *vcpu,
		     struct kvm_segment *var, int seg)
{
	kvm_x86_ops->get_segment(vcpu, var, seg);
}

gpa_t translate_nested_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
			   struct x86_exception *exception)
{
	gpa_t t_gpa;

	BUG_ON(!mmu_is_nested(vcpu));

	/* NPT walks are always user-walks */
	access |= PFERR_USER_MASK;
	t_gpa  = vcpu->arch.mmu.gva_to_gpa(vcpu, gpa, access, exception);

	return t_gpa;
}

gpa_t kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva,
			      struct x86_exception *exception)
{
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	return vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, exception);
}

 gpa_t kvm_mmu_gva_to_gpa_fetch(struct kvm_vcpu *vcpu, gva_t gva,
				struct x86_exception *exception)
{
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	access |= PFERR_FETCH_MASK;
	return vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, exception);
}

gpa_t kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva,
			       struct x86_exception *exception)
{
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	access |= PFERR_WRITE_MASK;
	return vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, exception);
}

/* uses this to access any guest's mapped memory without checking CPL */
gpa_t kvm_mmu_gva_to_gpa_system(struct kvm_vcpu *vcpu, gva_t gva,
				struct x86_exception *exception)
{
	return vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, 0, exception);
}

static int kvm_read_guest_virt_helper(gva_t addr, void *val, unsigned int bytes,
				      struct kvm_vcpu *vcpu, u32 access,
				      struct x86_exception *exception)
{
	void *data = val;
	char *__data;
	int r = X86EMUL_CONTINUE;

	while (bytes) {
		gpa_t gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, access,
							    exception);
		unsigned offset = addr & (PAGE_SIZE-1);
		unsigned toread = min(bytes, (unsigned)PAGE_SIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return X86EMUL_PROPAGATE_FAULT;
		ret = kvm_vcpu_read_guest_page(vcpu, gpa >> PAGE_SHIFT, data,
					       offset, toread);
		if (ret < 0) {
			r = X86EMUL_IO_NEEDED;
			goto out;
		}

		bytes -= toread;
		__data = (char *)data;
		__data += toread;
		data = (void *)__data;
		addr += toread;
	}
out:
	return r;
}

/* used for instruction fetching */
static int kvm_fetch_guest_virt(struct x86_emulate_ctxt *ctxt,
				gva_t addr, void *val, unsigned int bytes,
				struct x86_exception *exception)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	unsigned offset;
	int ret;

	/* Inline kvm_read_guest_virt_helper for speed.  */
	gpa_t gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, access|PFERR_FETCH_MASK,
						    exception);
	if (unlikely(gpa == UNMAPPED_GVA))
		return X86EMUL_PROPAGATE_FAULT;

	offset = addr & (PAGE_SIZE-1);
	if (WARN_ON(offset + bytes > PAGE_SIZE))
		bytes = (unsigned)PAGE_SIZE - offset;
	ret = kvm_vcpu_read_guest_page(vcpu, gpa >> PAGE_SHIFT, val,
				       offset, bytes);
	if (unlikely(ret < 0))
		return X86EMUL_IO_NEEDED;

	return X86EMUL_CONTINUE;
}

int kvm_read_guest_virt(struct x86_emulate_ctxt *ctxt,
			       gva_t addr, void *val, unsigned int bytes,
			       struct x86_exception *exception)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;

	return kvm_read_guest_virt_helper(addr, val, bytes, vcpu, access,
					  exception);
}

static int kvm_read_guest_virt_system(struct x86_emulate_ctxt *ctxt,
				      gva_t addr, void *val, unsigned int bytes,
				      struct x86_exception *exception)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	return kvm_read_guest_virt_helper(addr, val, bytes, vcpu, 0, exception);
}

static int kvm_read_guest_phys_system(struct x86_emulate_ctxt *ctxt,
		size_t addr, void *val, unsigned int bytes)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	int r = kvm_vcpu_read_guest(vcpu, addr, val, bytes);

	return r < 0 ? X86EMUL_IO_NEEDED : X86EMUL_CONTINUE;
}

int kvm_write_guest_virt_system(struct x86_emulate_ctxt *ctxt,
				       gva_t addr, void *val,
				       unsigned int bytes,
				       struct x86_exception *exception)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	void *data = val;
	char *__data;
	int r = X86EMUL_CONTINUE;

	while (bytes) {
		gpa_t gpa =  vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr,
							     PFERR_WRITE_MASK,
							     exception);
		unsigned offset = addr & (PAGE_SIZE-1);
		unsigned towrite = min(bytes, (unsigned)PAGE_SIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return X86EMUL_PROPAGATE_FAULT;
		ret = kvm_vcpu_write_guest(vcpu, gpa, data, towrite);
		if (ret < 0) {
			r = X86EMUL_IO_NEEDED;
			goto out;
		}

		bytes -= towrite;
		__data = (char *)data;
		__data += towrite;
		data = (void *)__data;
		addr += towrite;
	}
out:
	return r;
}

static int vcpu_mmio_gva_to_gpa(struct kvm_vcpu *vcpu, size_t gva,
				gpa_t *gpa, struct x86_exception *exception,
				bool write)
{
	u32 access = ((kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0)
		| (write ? PFERR_WRITE_MASK : 0);

	/*
	 * currently PKRU is only applied to ept enabled guest so
	 * there is no pkey in EPT page table for L1 guest or EPT
	 * shadow page table for L2 guest.
	 */
	if (vcpu_match_mmio_gva(vcpu, gva)
	    && !permission_fault(vcpu, vcpu->arch.walk_mmu,
				 vcpu->arch.access, 0, access)) {
		*gpa = vcpu->arch.mmio_gfn << PAGE_SHIFT |
					(gva & (PAGE_SIZE - 1));
		return 1;
	}

	*gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, exception);

	if (*gpa == UNMAPPED_GVA)
		return -1;

	/* For APIC access vmexit */
	if ((*gpa & PAGE_MASK) == APIC_DEFAULT_PHYS_BASE)
		return 1;

	if (vcpu_match_mmio_gpa(vcpu, *gpa)) {
		return 1;
	}

	return 0;
}

int emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
			const void *val, int bytes)
{
	int ret;

	ret = kvm_vcpu_write_guest(vcpu, gpa, val, bytes);
	if (ret < 0)
		return 0;
	kvm_page_track_write(vcpu, gpa, val, bytes);
	return 1;
}

struct read_write_emulator_ops {
	int (*read_write_prepare)(struct kvm_vcpu *vcpu, void *val,
				  int bytes);
	int (*read_write_emulate)(struct kvm_vcpu *vcpu, gpa_t gpa,
				  void *val, int bytes);
	int (*read_write_mmio)(struct kvm_vcpu *vcpu, gpa_t gpa,
			       int bytes, void *val);
	int (*read_write_exit_mmio)(struct kvm_vcpu *vcpu, gpa_t gpa,
				    void *val, int bytes);
	bool write;
};

static int read_prepare(struct kvm_vcpu *vcpu, void *val, int bytes)
{
	if (vcpu->mmio_read_completed) {
		vcpu->mmio_read_completed = 0;
		return 1;
	}

	return 0;
}

static int read_emulate(struct kvm_vcpu *vcpu, gpa_t gpa,
			void *val, int bytes)
{
	return !kvm_vcpu_read_guest(vcpu, gpa, val, bytes);
}

static int write_emulate(struct kvm_vcpu *vcpu, gpa_t gpa,
			 void *val, int bytes)
{
	return emulator_write_phys(vcpu, gpa, val, bytes);
}

static int write_mmio(struct kvm_vcpu *vcpu, gpa_t gpa, int bytes, void *val)
{
	return vcpu_mmio_write(vcpu, gpa, bytes, val);
}

static int read_exit_mmio(struct kvm_vcpu *vcpu, gpa_t gpa,
			  void *val, int bytes)
{
	return X86EMUL_IO_NEEDED;
}

static int write_exit_mmio(struct kvm_vcpu *vcpu, gpa_t gpa,
			   void *val, int bytes)
{
	struct kvm_mmio_fragment *frag = &vcpu->mmio_fragments[0];

	memcpy(vcpu->run->mmio.data, frag->data, min(8u, frag->len));
	return X86EMUL_CONTINUE;
}

static const struct read_write_emulator_ops read_emultor = {
	.read_write_prepare = read_prepare,
	.read_write_emulate = read_emulate,
	.read_write_mmio = vcpu_mmio_read,
	.read_write_exit_mmio = read_exit_mmio,
};

static const struct read_write_emulator_ops write_emultor = {
	.read_write_emulate = write_emulate,
	.read_write_mmio = write_mmio,
	.read_write_exit_mmio = write_exit_mmio,
	.write = true,
};

static int emulator_read_write_onepage(size_t addr, void *val,
				       unsigned int bytes,
				       struct x86_exception *exception,
				       struct kvm_vcpu *vcpu,
				       const struct read_write_emulator_ops *ops)
{
	gpa_t gpa;
	int handled, ret;
	bool write = ops->write;
	struct kvm_mmio_fragment *frag;
	char *__val;

	ret = vcpu_mmio_gva_to_gpa(vcpu, addr, &gpa, exception, write);

	if (ret < 0)
		return X86EMUL_PROPAGATE_FAULT;

	/* For APIC access vmexit */
	if (ret)
		goto mmio;

	if (ops->read_write_emulate(vcpu, gpa, val, bytes))
		return X86EMUL_CONTINUE;

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	handled = ops->read_write_mmio(vcpu, gpa, bytes, val);
	if (handled == bytes)
		return X86EMUL_CONTINUE;

	gpa += handled;
	bytes -= handled;
	__val = val;
	__val += handled;
	val = __val;

	WARN_ON(vcpu->mmio_nr_fragments >= GVM_MAX_MMIO_FRAGMENTS);
	frag = &vcpu->mmio_fragments[vcpu->mmio_nr_fragments++];
	frag->gpa = gpa;
	frag->data = val;
	frag->len = bytes;
	return X86EMUL_CONTINUE;
}

static int emulator_read_write(struct x86_emulate_ctxt *ctxt,
			size_t addr,
			void *val, unsigned int bytes,
			struct x86_exception *exception,
			const struct read_write_emulator_ops *ops)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	gpa_t gpa;
	int rc;
	char *__val;

	if (ops->read_write_prepare &&
		  ops->read_write_prepare(vcpu, val, bytes))
		return X86EMUL_CONTINUE;

	vcpu->mmio_nr_fragments = 0;

	/* Crossing a page boundary? */
	if (((addr + bytes - 1) ^ addr) & PAGE_MASK) {
		int now;

		now = -(ssize_t)addr & ~PAGE_MASK;
		rc = emulator_read_write_onepage(addr, val, now, exception,
						 vcpu, ops);

		if (rc != X86EMUL_CONTINUE)
			return rc;
		addr += now;
		if (ctxt->mode != X86EMUL_MODE_PROT64)
			addr = (u32)addr;
		__val = val;
		__val += now;
		val = __val;
		bytes -= now;
	}

	rc = emulator_read_write_onepage(addr, val, bytes, exception,
					 vcpu, ops);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (!vcpu->mmio_nr_fragments)
		return rc;

	gpa = vcpu->mmio_fragments[0].gpa;

	vcpu->mmio_needed = 1;
	vcpu->mmio_cur_fragment = 0;

	vcpu->run->mmio.len = min(8u, vcpu->mmio_fragments[0].len);
	vcpu->run->mmio.is_write = vcpu->mmio_is_write = ops->write;
	vcpu->run->exit_reason = GVM_EXIT_MMIO;
	vcpu->run->mmio.phys_addr = gpa;

	return ops->read_write_exit_mmio(vcpu, gpa, val, bytes);
}

static int emulator_read_emulated(struct x86_emulate_ctxt *ctxt,
				  size_t addr,
				  void *val,
				  unsigned int bytes,
				  struct x86_exception *exception)
{
	return emulator_read_write(ctxt, addr, val, bytes,
				   exception, &read_emultor);
}

static int emulator_write_emulated(struct x86_emulate_ctxt *ctxt,
			    size_t addr,
			    const void *val,
			    unsigned int bytes,
			    struct x86_exception *exception)
{
	return emulator_read_write(ctxt, addr, (void *)val, bytes,
				   exception, &write_emultor);
}

#define CMPXCHG_TYPE(t, ptr, old, new) \
	(cmpxchg((t *)(ptr), *(t *)(old), *(t *)(new)) == *(t *)(old))

#ifdef CONFIG_X86_64
#  define CMPXCHG64(ptr, old, new) CMPXCHG_TYPE(u64, ptr, old, new)
#else
#  define CMPXCHG64(ptr, old, new) \
	(cmpxchg64((u64 *)(ptr), *(u64 *)(old), *(u64 *)(new)) == *(u64 *)(old))
#endif

static int emulator_cmpxchg_emulated(struct x86_emulate_ctxt *ctxt,
				     size_t addr,
				     const void *old,
				     const void *new,
				     unsigned int bytes,
				     struct x86_exception *exception)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	gpa_t gpa;
	char *kaddr;
	bool exchanged;
	size_t hva;
	PMDL kmap_mdl;

	/* guests cmpxchg8b have to be emulated atomically */
	if (bytes > 8 || (bytes & (bytes - 1)))
		goto emul_write;

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, NULL);

	if (gpa == UNMAPPED_GVA ||
	    (gpa & PAGE_MASK) == APIC_DEFAULT_PHYS_BASE)
		goto emul_write;

	if (((gpa + bytes - 1) & PAGE_MASK) != (gpa & PAGE_MASK))
		goto emul_write;

	hva = gfn_to_hva(vcpu->kvm, gpa >> PAGE_SHIFT);
	if (kvm_is_error_hva(hva))
		goto emul_write;

	if (get_user_pages_fast(hva, 1, 1, &kmap_mdl) != 1)
		goto emul_write;

	kaddr = kmap_atomic(kmap_mdl);
	if (!kaddr)
		goto emul_write;
	kaddr += offset_in_page(gpa);
	switch (bytes) {
	case 1:
		exchanged = CMPXCHG_TYPE(u8, kaddr, old, new);
		break;
	case 2:
		exchanged = CMPXCHG_TYPE(u16, kaddr, old, new);
		break;
	case 4:
		exchanged = CMPXCHG_TYPE(u32, kaddr, old, new);
		break;
	case 8:
		exchanged = CMPXCHG64(kaddr, old, new);
		break;
	default:
		BUG();
	}
	kunmap_atomic(kmap_mdl);

	if (!exchanged)
		return X86EMUL_CMPXCHG_FAILED;

	kvm_vcpu_mark_page_dirty(vcpu, gpa >> PAGE_SHIFT);
	kvm_page_track_write(vcpu, gpa, new, bytes);

	return X86EMUL_CONTINUE;

emul_write:
	printk_once(KERN_WARNING "kvm: emulating exchange as write\n");

	return emulator_write_emulated(ctxt, addr, new, bytes, exception);
}

static int kernel_pio(struct kvm_vcpu *vcpu, void *pd)
{
	/* TODO: String I/O for in kernel device */
	int r;

	if (vcpu->arch.pio.in)
		r = kvm_io_bus_read(vcpu, GVM_PIO_BUS, vcpu->arch.pio.port,
				    vcpu->arch.pio.size, pd);
	else
		r = kvm_io_bus_write(vcpu, GVM_PIO_BUS,
				     vcpu->arch.pio.port, vcpu->arch.pio.size,
				     pd);
	return r;
}

static int emulator_pio_in_out(struct kvm_vcpu *vcpu, int size,
			       unsigned short port, void *val,
			       unsigned int count, bool in)
{
	vcpu->arch.pio.port = port;
	vcpu->arch.pio.in = in;
	vcpu->arch.pio.count  = count;
	vcpu->arch.pio.size = size;

	if (!kernel_pio(vcpu, vcpu->arch.pio_data)) {
		vcpu->arch.pio.count = 0;
		return 1;
	}

	vcpu->run->exit_reason = GVM_EXIT_IO;
	vcpu->run->io.direction = in ? GVM_EXIT_IO_IN : GVM_EXIT_IO_OUT;
	vcpu->run->io.size = size;
	vcpu->run->io.data_offset = GVM_PIO_PAGE_OFFSET * PAGE_SIZE;
	vcpu->run->io.count = count;
	vcpu->run->io.port = port;

	return 0;
}

static int emulator_pio_in_emulated(struct x86_emulate_ctxt *ctxt,
				    int size, unsigned short port, void *val,
				    unsigned int count)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	int ret;

	if (vcpu->arch.pio.count)
		goto data_avail;

	ret = emulator_pio_in_out(vcpu, size, port, val, count, true);
	if (ret) {
data_avail:
		memcpy(val, vcpu->arch.pio_data, size * count);
		vcpu->arch.pio.count = 0;
		return 1;
	}

	return 0;
}

static int emulator_pio_out_emulated(struct x86_emulate_ctxt *ctxt,
				     int size, unsigned short port,
				     const void *val, unsigned int count)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);

	memcpy(vcpu->arch.pio_data, val, size * count);
	return emulator_pio_in_out(vcpu, size, port, (void *)val, count, false);
}

static size_t get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return kvm_x86_ops->get_segment_base(vcpu, seg);
}

static void emulator_invlpg(struct x86_emulate_ctxt *ctxt, ulong address)
{
	kvm_mmu_invlpg(emul_to_vcpu(ctxt), address);
}

int kvm_emulate_wbinvd_noskip(struct kvm_vcpu *vcpu)
{
	return X86EMUL_CONTINUE;
}

int kvm_emulate_wbinvd(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->skip_emulated_instruction(vcpu);
	return kvm_emulate_wbinvd_noskip(vcpu);
}



static void emulator_wbinvd(struct x86_emulate_ctxt *ctxt)
{
	kvm_emulate_wbinvd_noskip(emul_to_vcpu(ctxt));
}

static int emulator_get_dr(struct x86_emulate_ctxt *ctxt, int dr,
			   size_t *dest)
{
	//return kvm_get_dr(emul_to_vcpu(ctxt), dr, dest);
	return 0;
}

static int emulator_set_dr(struct x86_emulate_ctxt *ctxt, int dr,
			   size_t value)
{
	return 0;
	//return __kvm_set_dr(emul_to_vcpu(ctxt), dr, value);
}

static u64 mk_cr_64(u64 curr_cr, u32 new_val)
{
	return (curr_cr & ~((1ULL << 32) - 1)) | new_val;
}

static size_t emulator_get_cr(struct x86_emulate_ctxt *ctxt, int cr)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	size_t value;

	switch (cr) {
	case 0:
		value = kvm_read_cr0(vcpu);
		break;
	case 2:
		value = vcpu->arch.cr2;
		break;
	case 3:
		value = kvm_read_cr3(vcpu);
		break;
	case 4:
		value = kvm_read_cr4(vcpu);
		break;
	case 8:
		value = kvm_get_cr8(vcpu);
		break;
	default:
		//kvm_err("%s: unexpected cr %u\n", __func__, cr);
		return 0;
	}

	return value;
}

static int emulator_set_cr(struct x86_emulate_ctxt *ctxt, int cr, ulong val)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	int res = 0;

	switch (cr) {
	case 0:
		res = kvm_set_cr0(vcpu, mk_cr_64(kvm_read_cr0(vcpu), val));
		break;
	case 2:
		vcpu->arch.cr2 = val;
		break;
	case 3:
		res = kvm_set_cr3(vcpu, val);
		break;
	case 4:
		res = kvm_set_cr4(vcpu, mk_cr_64(kvm_read_cr4(vcpu), val));
		break;
	case 8:
		res = kvm_set_cr8(vcpu, val);
		break;
	default:
		//kvm_err("%s: unexpected cr %u\n", __func__, cr);
		res = -1;
	}

	return res;
}

static int emulator_get_cpl(struct x86_emulate_ctxt *ctxt)
{
	return kvm_x86_ops->get_cpl(emul_to_vcpu(ctxt));
}

static void emulator_get_gdt(struct x86_emulate_ctxt *ctxt, struct desc_ptr *dt)
{
	kvm_x86_ops->get_gdt(emul_to_vcpu(ctxt), dt);
}

static void emulator_get_idt(struct x86_emulate_ctxt *ctxt, struct desc_ptr *dt)
{
	kvm_x86_ops->get_idt(emul_to_vcpu(ctxt), dt);
}

static void emulator_set_gdt(struct x86_emulate_ctxt *ctxt, struct desc_ptr *dt)
{
	kvm_x86_ops->set_gdt(emul_to_vcpu(ctxt), dt);
}

static void emulator_set_idt(struct x86_emulate_ctxt *ctxt, struct desc_ptr *dt)
{
	kvm_x86_ops->set_idt(emul_to_vcpu(ctxt), dt);
}

static size_t emulator_get_cached_segment_base(
	struct x86_emulate_ctxt *ctxt, int seg)
{
	return get_segment_base(emul_to_vcpu(ctxt), seg);
}

static bool emulator_get_segment(struct x86_emulate_ctxt *ctxt, u16 *selector,
				 struct desc_struct *desc, u32 *base3,
				 int seg)
{
	struct kvm_segment var;

	kvm_get_segment(emul_to_vcpu(ctxt), &var, seg);
	*selector = var.selector;

	if (var.unusable) {
		memset(desc, 0, sizeof(*desc));
		return false;
	}

	if (var.g)
		var.limit >>= 12;
	set_desc_limit(desc, var.limit);
	set_desc_base(desc, (size_t)var.base);
#ifdef CONFIG_X86_64
	if (base3)
		*base3 = var.base >> 32;
#endif
	desc->type = var.type;
	desc->s = var.s;
	desc->dpl = var.dpl;
	desc->p = var.present;
	desc->avl = var.avl;
	desc->l = var.l;
	desc->d = var.db;
	desc->g = var.g;

	return true;
}

static void emulator_set_segment(struct x86_emulate_ctxt *ctxt, u16 selector,
				 struct desc_struct *desc, u32 base3,
				 int seg)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	struct kvm_segment var;

	var.selector = selector;
	var.base = get_desc_base(desc);
#ifdef CONFIG_X86_64
	var.base |= ((u64)base3) << 32;
#endif
	var.limit = get_desc_limit(desc);
	if (desc->g)
		var.limit = (var.limit << 12) | 0xfff;
	var.type = desc->type;
	var.dpl = desc->dpl;
	var.db = desc->d;
	var.s = desc->s;
	var.l = desc->l;
	var.g = desc->g;
	var.avl = desc->avl;
	var.present = desc->p;
	var.unusable = !var.present;
	var.padding = 0;

	kvm_set_segment(vcpu, &var, seg);
	return;
}

static int emulator_get_msr(struct x86_emulate_ctxt *ctxt,
			    u32 msr_index, u64 *pdata)
{
	struct msr_data msr;
	int r;

	msr.index = msr_index;
	msr.host_initiated = false;
	r = kvm_get_msr(emul_to_vcpu(ctxt), &msr);
	if (r)
		return r;

	*pdata = msr.data;
	return 0;
}

static int emulator_set_msr(struct x86_emulate_ctxt *ctxt,
			    u32 msr_index, u64 data)
{
	struct msr_data msr;

	msr.data = data;
	msr.index = msr_index;
	msr.host_initiated = false;
	return kvm_set_msr(emul_to_vcpu(ctxt), &msr);
}

static u64 emulator_get_smbase(struct x86_emulate_ctxt *ctxt)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);

	return vcpu->arch.smbase;
}

static void emulator_set_smbase(struct x86_emulate_ctxt *ctxt, u64 smbase)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);

	vcpu->arch.smbase = smbase;
}

static int emulator_check_pmc(struct x86_emulate_ctxt *ctxt,
			      u32 pmc)
{
	//return kvm_pmu_is_valid_msr_idx(emul_to_vcpu(ctxt), pmc);
	return 0;
}

static int emulator_read_pmc(struct x86_emulate_ctxt *ctxt,
			     u32 pmc, u64 *pdata)
{
	//return kvm_pmu_rdpmc(emul_to_vcpu(ctxt), pmc, pdata);
	return 0;
}

static void emulator_halt(struct x86_emulate_ctxt *ctxt)
{
	emul_to_vcpu(ctxt)->arch.halt_request = 1;
}

static void emulator_get_fpu(struct x86_emulate_ctxt *ctxt)
{
	preempt_disable();
	kvm_load_guest_fpu(emul_to_vcpu(ctxt));
	/*
	 * CR0.TS may reference the host fpu state, not the guest fpu state,
	 * so it may be clear at this point.
	 */
	__clts();
}

static void emulator_put_fpu(struct x86_emulate_ctxt *ctxt)
{
	kvm_save_guest_fpu(emul_to_vcpu(ctxt));
	preempt_enable();
}

static int emulator_intercept(struct x86_emulate_ctxt *ctxt,
			      struct x86_instruction_info *info,
			      enum x86_intercept_stage stage)
{
	return kvm_x86_ops->check_intercept(emul_to_vcpu(ctxt), info, stage);
}

static void emulator_get_cpuid(struct x86_emulate_ctxt *ctxt,
			       u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	kvm_cpuid(emul_to_vcpu(ctxt), eax, ebx, ecx, edx);
}

static ulong emulator_read_gpr(struct x86_emulate_ctxt *ctxt, unsigned reg)
{
	return kvm_register_read(emul_to_vcpu(ctxt), reg);
}

static void emulator_write_gpr(struct x86_emulate_ctxt *ctxt, unsigned reg, ulong val)
{
	kvm_register_write(emul_to_vcpu(ctxt), reg, val);
}

static void emulator_set_nmi_mask(struct x86_emulate_ctxt *ctxt, bool masked)
{
	kvm_x86_ops->set_nmi_mask(emul_to_vcpu(ctxt), masked);
}

static const struct x86_emulate_ops emulate_ops = {
	.read_gpr            = emulator_read_gpr,
	.write_gpr           = emulator_write_gpr,
	.read_std            = kvm_read_guest_virt_system,
	.write_std           = kvm_write_guest_virt_system,
	.read_phys           = kvm_read_guest_phys_system,
	.fetch               = kvm_fetch_guest_virt,
	.read_emulated       = emulator_read_emulated,
	.write_emulated      = emulator_write_emulated,
	.cmpxchg_emulated    = emulator_cmpxchg_emulated,
	.invlpg              = emulator_invlpg,
	.pio_in_emulated     = emulator_pio_in_emulated,
	.pio_out_emulated    = emulator_pio_out_emulated,
	.get_segment         = emulator_get_segment,
	.set_segment         = emulator_set_segment,
	.get_cached_segment_base = emulator_get_cached_segment_base,
	.get_gdt             = emulator_get_gdt,
	.get_idt	     = emulator_get_idt,
	.set_gdt             = emulator_set_gdt,
	.set_idt	     = emulator_set_idt,
	.get_cr              = emulator_get_cr,
	.set_cr              = emulator_set_cr,
	.cpl                 = emulator_get_cpl,
	.get_dr              = emulator_get_dr,
	.set_dr              = emulator_set_dr,
	.get_smbase          = emulator_get_smbase,
	.set_smbase          = emulator_set_smbase,
	.set_msr             = emulator_set_msr,
	.get_msr             = emulator_get_msr,
	.check_pmc	     = emulator_check_pmc,
	.read_pmc            = emulator_read_pmc,
	.halt                = emulator_halt,
	.wbinvd              = emulator_wbinvd,
	.get_fpu             = emulator_get_fpu,
	.put_fpu             = emulator_put_fpu,
	.intercept           = emulator_intercept,
	.get_cpuid           = emulator_get_cpuid,
	.set_nmi_mask        = emulator_set_nmi_mask,
};

static void toggle_interruptibility(struct kvm_vcpu *vcpu, u32 mask)
{
	u32 int_shadow = kvm_x86_ops->get_interrupt_shadow(vcpu);
	/*
	 * an sti; sti; sequence only disable interrupts for the first
	 * instruction. So, if the last instruction, be it emulated or
	 * not, left the system with the INT_STI flag enabled, it
	 * means that the last instruction is an sti. We should not
	 * leave the flag on in this case. The same goes for mov ss
	 */
	if (int_shadow & mask)
		mask = 0;
	if (unlikely(int_shadow || mask)) {
		kvm_x86_ops->set_interrupt_shadow(vcpu, mask);
		if (!mask)
			kvm_make_request(GVM_REQ_EVENT, vcpu);
	}
}

static bool inject_emulated_exception(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	if (ctxt->exception.vector == PF_VECTOR)
		return kvm_propagate_fault(vcpu, &ctxt->exception);

	if (ctxt->exception.error_code_valid)
		kvm_queue_exception_e(vcpu, ctxt->exception.vector,
				      ctxt->exception.error_code);
	else
		kvm_queue_exception(vcpu, ctxt->exception.vector);
	return false;
}

static void init_emulate_ctxt(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	int cs_db, cs_l;

	kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);

	ctxt->eflags = kvm_get_rflags(vcpu);
	ctxt->eip = kvm_rip_read(vcpu);
	ctxt->mode = (!is_protmode(vcpu))		? X86EMUL_MODE_REAL :
		     (ctxt->eflags & X86_EFLAGS_VM)	? X86EMUL_MODE_VM86 :
		     (cs_l && is_long_mode(vcpu))	? X86EMUL_MODE_PROT64 :
		     cs_db				? X86EMUL_MODE_PROT32 :
							  X86EMUL_MODE_PROT16;
	ctxt->emul_flags = vcpu->arch.hflags;

	init_decode_cache(ctxt);
	vcpu->arch.emulate_regs_need_sync_from_vcpu = false;
}

int kvm_inject_realmode_interrupt(struct kvm_vcpu *vcpu, int irq, int inc_eip)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	int ret;

	init_emulate_ctxt(vcpu);

	ctxt->op_bytes = 2;
	ctxt->ad_bytes = 2;
	ctxt->_eip = ctxt->eip + inc_eip;
	ret = emulate_int_real(ctxt, irq);

	if (ret != X86EMUL_CONTINUE)
		return EMULATE_FAIL;

	ctxt->eip = ctxt->_eip;
	kvm_rip_write(vcpu, ctxt->eip);
	kvm_set_rflags(vcpu, ctxt->eflags);

	if (irq == NMI_VECTOR)
		vcpu->arch.nmi_pending = 0;
	else
		vcpu->arch.interrupt.pending = false;

	return EMULATE_DONE;
}

static int handle_emulation_failure(struct kvm_vcpu *vcpu)
{
	int r = EMULATE_DONE;

	++vcpu->stat.insn_emulation_fail;
	if (!is_guest_mode(vcpu) && kvm_x86_ops->get_cpl(vcpu) == 0) {
		vcpu->run->exit_reason = GVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = GVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		r = EMULATE_FAIL;
	}
	kvm_queue_exception(vcpu, UD_VECTOR);

	return r;
}

static bool reexecute_instruction(struct kvm_vcpu *vcpu, gva_t cr2,
				  bool write_fault_to_shadow_pgtable,
				  int emulation_type)
{
	gpa_t gpa = cr2;
	kvm_pfn_t pfn;

	if (emulation_type & EMULTYPE_NO_REEXECUTE)
		return false;

	if (!vcpu->arch.mmu.direct_map) {
		/*
		 * Write permission should be allowed since only
		 * write access need to be emulated.
		 */
		gpa = kvm_mmu_gva_to_gpa_write(vcpu, cr2, NULL);

		/*
		 * If the mapping is invalid in guest, let cpu retry
		 * it to generate fault.
		 */
		if (gpa == UNMAPPED_GVA)
			return true;
	}

	/*
	 * Do not retry the unhandleable instruction if it faults on the
	 * readonly host memory, otherwise it will goto a infinite loop:
	 * retry instruction -> write #PF -> emulation fail -> retry
	 * instruction -> ...
	 */
	pfn = gfn_to_pfn(vcpu->kvm, gpa_to_gfn(gpa));

	/*
	 * If the instruction failed on the error pfn, it can not be fixed,
	 * report the error to userspace.
	 */
	if (is_error_noslot_pfn(pfn))
		return false;

	/* The instructions are well-emulated on direct mmu. */
	if (vcpu->arch.mmu.direct_map) {
		unsigned int indirect_shadow_pages;

		spin_lock(&vcpu->kvm->mmu_lock);
		indirect_shadow_pages = vcpu->kvm->arch.indirect_shadow_pages;
		spin_unlock(&vcpu->kvm->mmu_lock);

		if (indirect_shadow_pages)
			kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(gpa));

		return true;
	}

	/*
	 * if emulation was due to access to shadowed page table
	 * and it failed try to unshadow page and re-enter the
	 * guest to let CPU execute the instruction.
	 */
	kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(gpa));

	/*
	 * If the access faults on its page table, it can not
	 * be fixed by unprotecting shadow page and it should
	 * be reported to userspace.
	 */
	return !write_fault_to_shadow_pgtable;
}

static bool retry_instruction(struct x86_emulate_ctxt *ctxt,
			      size_t cr2,  int emulation_type)
{
	struct kvm_vcpu *vcpu = emul_to_vcpu(ctxt);
	size_t last_retry_eip, last_retry_addr, gpa = cr2;

	last_retry_eip = vcpu->arch.last_retry_eip;
	last_retry_addr = vcpu->arch.last_retry_addr;

	/*
	 * If the emulation is caused by #PF and it is non-page_table
	 * writing instruction, it means the VM-EXIT is caused by shadow
	 * page protected, we can zap the shadow page and retry this
	 * instruction directly.
	 *
	 * Note: if the guest uses a non-page-table modifying instruction
	 * on the PDE that points to the instruction, then we will unmap
	 * the instruction and go to an infinite loop. So, we cache the
	 * last retried eip and the last fault address, if we meet the eip
	 * and the address again, we can break out of the potential infinite
	 * loop.
	 */
	vcpu->arch.last_retry_eip = vcpu->arch.last_retry_addr = 0;

	if (!(emulation_type & EMULTYPE_RETRY))
		return false;

	if (x86_page_table_writing_insn(ctxt))
		return false;

	if (ctxt->eip == last_retry_eip && last_retry_addr == cr2)
		return false;

	vcpu->arch.last_retry_eip = ctxt->eip;
	vcpu->arch.last_retry_addr = cr2;

	if (!vcpu->arch.mmu.direct_map)
		gpa = kvm_mmu_gva_to_gpa_write(vcpu, cr2, NULL);

	kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(gpa));

	return true;
}

static int complete_emulated_mmio(struct kvm_vcpu *vcpu);
static int complete_emulated_pio(struct kvm_vcpu *vcpu);

static void kvm_smm_changed(struct kvm_vcpu *vcpu)
{
	if (!(vcpu->arch.hflags & HF_SMM_MASK)) {
		/* Process a latched INIT or SMI, if any.  */
		kvm_make_request(GVM_REQ_EVENT, vcpu);
	}

	kvm_mmu_reset_context(vcpu);
}

static void kvm_set_hflags(struct kvm_vcpu *vcpu, unsigned emul_flags)
{
	unsigned changed = vcpu->arch.hflags ^ emul_flags;

	vcpu->arch.hflags = emul_flags;

	if (changed & HF_SMM_MASK)
		kvm_smm_changed(vcpu);
}

static int kvm_vcpu_check_hw_bp(size_t addr, u32 type, u32 dr7,
				size_t *db)
{
	u32 dr6 = 0;
	int i;
	u32 enable, rwlen;

	enable = dr7;
	rwlen = dr7 >> 16;
	for (i = 0; i < 4; i++, enable >>= 2, rwlen >>= 4)
		if ((enable & 3) && (rwlen & 15) == type && db[i] == addr)
			dr6 |= (1 << i);
	return dr6;
}

static void kvm_vcpu_check_singlestep(struct kvm_vcpu *vcpu, size_t rflags, int *r)
{
	struct kvm_run *kvm_run = vcpu->run;

	/*
	 * rflags is the old, "raw" value of the flags.  The new value has
	 * not been saved yet.
	 *
	 * This is correct even for TF set by the guest, because "the
	 * processor will not generate this exception after the instruction
	 * that sets the TF flag".
	 */
	if (unlikely(rflags & X86_EFLAGS_TF)) {
		if (vcpu->guest_debug & GVM_GUESTDBG_SINGLESTEP) {
			kvm_run->debug.arch.dr6 = DR6_BS | DR6_FIXED_1 |
						  DR6_RTM;
			kvm_run->debug.arch.pc = vcpu->arch.singlestep_rip;
			kvm_run->debug.arch.exception = DB_VECTOR;
			kvm_run->exit_reason = GVM_EXIT_DEBUG;
			*r = EMULATE_USER_EXIT;
		} else {
			vcpu->arch.emulate_ctxt.eflags &= ~X86_EFLAGS_TF;
			/*
			 * "Certain debug exceptions may clear bit 0-3.  The
			 * remaining contents of the DR6 register are never
			 * cleared by the processor".
			 */
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= DR6_BS | DR6_RTM;
			kvm_queue_exception(vcpu, DB_VECTOR);
		}
	}
}

static bool kvm_vcpu_check_breakpoint(struct kvm_vcpu *vcpu, int *r)
{
	if (unlikely(vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP) &&
	    (vcpu->arch.guest_debug_dr7 & DR7_BP_EN_MASK)) {
		struct kvm_run *kvm_run = vcpu->run;
		size_t eip = kvm_get_linear_rip(vcpu);
		u32 dr6 = kvm_vcpu_check_hw_bp(eip, 0,
					   vcpu->arch.guest_debug_dr7,
					   vcpu->arch.eff_db);

		if (dr6 != 0) {
			kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1 | DR6_RTM;
			kvm_run->debug.arch.pc = eip;
			kvm_run->debug.arch.exception = DB_VECTOR;
			kvm_run->exit_reason = GVM_EXIT_DEBUG;
			*r = EMULATE_USER_EXIT;
			return true;
		}
	}

	if (unlikely(vcpu->arch.dr7 & DR7_BP_EN_MASK) &&
	    !(kvm_get_rflags(vcpu) & X86_EFLAGS_RF)) {
		size_t eip = kvm_get_linear_rip(vcpu);
		u32 dr6 = kvm_vcpu_check_hw_bp(eip, 0,
					   vcpu->arch.dr7,
					   vcpu->arch.db);

		if (dr6 != 0) {
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= dr6 | DR6_RTM;
			kvm_queue_exception(vcpu, DB_VECTOR);
			*r = EMULATE_DONE;
			return true;
		}
	}

	return false;
}

int x86_emulate_instruction(struct kvm_vcpu *vcpu,
			    size_t cr2,
			    int emulation_type,
			    void *insn,
			    int insn_len)
{
	int r;
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	bool writeback = true;
	bool write_fault_to_spt = vcpu->arch.write_fault_to_shadow_pgtable;

	/*
	 * Clear write_fault_to_shadow_pgtable here to ensure it is
	 * never reused.
	 */
	vcpu->arch.write_fault_to_shadow_pgtable = false;
	kvm_clear_exception_queue(vcpu);

	if (!(emulation_type & EMULTYPE_NO_DECODE)) {
		init_emulate_ctxt(vcpu);

		/*
		 * We will reenter on the same instruction since
		 * we do not set complete_userspace_io.  This does not
		 * handle watchpoints yet, those would be handled in
		 * the emulate_ops.
		 */
		if (kvm_vcpu_check_breakpoint(vcpu, &r))
			return r;

		ctxt->interruptibility = 0;
		ctxt->have_exception = false;
		ctxt->exception.vector = -1;
		ctxt->perm_ok = false;

		ctxt->ud = emulation_type & EMULTYPE_TRAP_UD;

		r = x86_decode_insn(ctxt, insn, insn_len);

		++vcpu->stat.insn_emulation;
		if (r != EMULATION_OK)  {
			if (emulation_type & EMULTYPE_TRAP_UD)
				return EMULATE_FAIL;
			if (reexecute_instruction(vcpu, cr2, write_fault_to_spt,
						emulation_type))
				return EMULATE_DONE;
			if (emulation_type & EMULTYPE_SKIP)
				return EMULATE_FAIL;
			return handle_emulation_failure(vcpu);
		}
	}

	if (emulation_type & EMULTYPE_SKIP) {
		kvm_rip_write(vcpu, ctxt->_eip);
		if (ctxt->eflags & X86_EFLAGS_RF)
			kvm_set_rflags(vcpu, ctxt->eflags & ~X86_EFLAGS_RF);
		return EMULATE_DONE;
	}

	if (retry_instruction(ctxt, cr2, emulation_type))
		return EMULATE_DONE;

	/* this is needed for vmware backdoor interface to work since it
	   changes registers values  during IO operation */
	if (vcpu->arch.emulate_regs_need_sync_from_vcpu) {
		vcpu->arch.emulate_regs_need_sync_from_vcpu = false;
		emulator_invalidate_register_cache(ctxt);
	}

restart:
	r = x86_emulate_insn(ctxt);

	if (r == EMULATION_INTERCEPTED)
		return EMULATE_DONE;

	if (r == EMULATION_FAILED) {
		if (reexecute_instruction(vcpu, cr2, write_fault_to_spt,
					emulation_type))
			return EMULATE_DONE;

		return handle_emulation_failure(vcpu);
	}

	if (ctxt->have_exception) {
		r = EMULATE_DONE;
		if (inject_emulated_exception(vcpu))
			return r;
	} else if (vcpu->arch.pio.count) {
		if (!vcpu->arch.pio.in) {
			/* FIXME: return into emulator if single-stepping.  */
			vcpu->arch.pio.count = 0;
		} else {
			writeback = false;
			vcpu->arch.complete_userspace_io = complete_emulated_pio;
		}
		r = EMULATE_USER_EXIT;
	} else if (vcpu->mmio_needed) {
		if (!vcpu->mmio_is_write)
			writeback = false;
		r = EMULATE_USER_EXIT;
		vcpu->arch.complete_userspace_io = complete_emulated_mmio;
	} else if (r == EMULATION_RESTART)
		goto restart;
	else
		r = EMULATE_DONE;

	if (writeback) {
		size_t rflags = kvm_x86_ops->get_rflags(vcpu);
		toggle_interruptibility(vcpu, ctxt->interruptibility);
		vcpu->arch.emulate_regs_need_sync_to_vcpu = false;
		if (vcpu->arch.hflags != ctxt->emul_flags)
			kvm_set_hflags(vcpu, ctxt->emul_flags);
		kvm_rip_write(vcpu, ctxt->eip);
		if (r == EMULATE_DONE)
			kvm_vcpu_check_singlestep(vcpu, rflags, &r);
		if (!ctxt->have_exception ||
		    exception_type(ctxt->exception.vector) == EXCPT_TRAP)
			__kvm_set_rflags(vcpu, ctxt->eflags);

		/*
		 * For STI, interrupts are shadowed; so GVM_REQ_EVENT will
		 * do nothing, and it will be requested again as soon as
		 * the shadow expires.  But we still need to check here,
		 * because POPF has no interrupt shadow.
		 */
		if (unlikely((ctxt->eflags & ~rflags) & X86_EFLAGS_IF))
			kvm_make_request(GVM_REQ_EVENT, vcpu);
	} else
		vcpu->arch.emulate_regs_need_sync_to_vcpu = true;

	return r;
}

int kvm_fast_pio_out(struct kvm_vcpu *vcpu, int size, unsigned short port)
{
	size_t val = kvm_register_read(vcpu, VCPU_REGS_RAX);
	int ret = emulator_pio_out_emulated(&vcpu->arch.emulate_ctxt,
					    size, port, &val, 1);
	/* do not return to emulator after return from userspace */
	vcpu->arch.pio.count = 0;
	return ret;
}

static DEFINE_PER_CPU(struct kvm_vcpu *, current_vcpu);

void kvm_before_handle_nmi(struct kvm_vcpu *vcpu)
{
	__this_cpu_write(current_vcpu, vcpu);
}

void kvm_after_handle_nmi(struct kvm_vcpu *vcpu)
{
	__this_cpu_write(current_vcpu, NULL);
}

static void kvm_set_mmio_spte_mask(void)
{
	u64 mask;
	int maxphyaddr = boot_cpu_data.x86_phys_bits;

	/*
	 * Set the reserved bits and the present bit of an paging-structure
	 * entry to generate page fault with PFER.RSV = 1.
	 */
	 /* Mask the reserved physical address bits. */
	mask = rsvd_bits(maxphyaddr, 51);

	/* Bit 62 is always reserved for 32bit host. */
	mask |= 0x3ull << 62;

	/* Set the present bit. */
	mask |= 1ull;

#ifdef CONFIG_X86_64
	/*
	 * If reserved bit is not supported, clear the present bit to disable
	 * mmio page fault.
	 */
	if (maxphyaddr == 52)
		mask &= ~1ull;
#endif

	kvm_mmu_set_mmio_spte_mask(mask);
}

int kvm_arch_init(void *opaque)
{
	int r = -EFAULT, i;
	struct kvm_x86_ops *ops = opaque;

	if (kvm_x86_ops) {
		printk(KERN_ERR "kvm: already loaded the other module\n");
		r = -EEXIST;
		goto out;
	}

	if (!ops->cpu_has_kvm_support()) {
		printk(KERN_ERR "kvm: no hardware support\n");
		r = -EOPNOTSUPP;
		goto out;
	}
	if (ops->disabled_by_bios()) {
		printk(KERN_ERR "kvm: disabled by bios\n");
		r = -EOPNOTSUPP;
		goto out;
	}

	kvm_set_mmio_spte_mask();

	kvm_x86_ops = ops;

	kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
			PT_DIRTY_MASK, PT64_NX_MASK, 0,
			PT_PRESENT_MASK);

	if (boot_cpu_has(X86_FEATURE_XSAVE))
		host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	/* We have to move array initialization here since gcc's extension
	 * of array initialization is not supported here.
	 */
	for (i = 0; i < XFEATURE_MAX; i++)
		xstate_offsets[i] = xstate_sizes[i] = -1;

	kvm_lapic_init();

	return 0;

out:
	return r;
}

void kvm_arch_exit(void)
{
	kvm_x86_ops = NULL;
	kvm_mmu_module_exit();
}

int kvm_vcpu_halt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.halt_exits;
	if (lapic_in_kernel(vcpu)) {
		vcpu->arch.mp_state = GVM_MP_STATE_HALTED;
		return 1;
	} else {
		vcpu->run->exit_reason = GVM_EXIT_HLT;
		return 0;
	}
}

int kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->skip_emulated_instruction(vcpu);
	return kvm_vcpu_halt(vcpu);
}

void kvm_vcpu_deactivate_apicv(struct kvm_vcpu *vcpu)
{
	vcpu->arch.apicv_active = false;
	kvm_x86_ops->refresh_apicv_exec_ctrl(vcpu);
}

static int dm_request_for_irq_injection(struct kvm_vcpu *vcpu)
{
	return vcpu->run->request_interrupt_window &&
		likely(!pic_in_kernel(vcpu->kvm));
}

static void post_kvm_run_save(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;

	kvm_run->if_flag = (kvm_get_rflags(vcpu) & X86_EFLAGS_IF) != 0;
	kvm_run->flags = is_smm(vcpu) ? GVM_RUN_X86_SMM : 0;
	kvm_run->cr8 = kvm_get_cr8(vcpu);
	kvm_run->apic_base = kvm_get_apic_base(vcpu);
	kvm_run->ready_for_interrupt_injection =
		pic_in_kernel(vcpu->kvm) ||
		kvm_vcpu_ready_for_interrupt_injection(vcpu);
}

static void update_cr8_intercept(struct kvm_vcpu *vcpu)
{
	int max_irr, tpr;

	if (!kvm_x86_ops->update_cr8_intercept)
		return;

	if (!lapic_in_kernel(vcpu))
		return;

	if (vcpu->arch.apicv_active)
		return;

	if (!vcpu->arch.apic->vapic_addr)
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	else
		max_irr = -1;

	if (max_irr != -1)
		max_irr >>= 4;

	tpr = kvm_lapic_get_cr8(vcpu);

	kvm_x86_ops->update_cr8_intercept(vcpu, tpr, max_irr);
}

static int inject_pending_event(struct kvm_vcpu *vcpu, bool req_int_win)
{
	int r;

	/* try to reinject previous events if any */
	if (vcpu->arch.exception.pending) {
		if (exception_type(vcpu->arch.exception.nr) == EXCPT_FAULT)
			__kvm_set_rflags(vcpu, kvm_get_rflags(vcpu) |
					     X86_EFLAGS_RF);

		if (vcpu->arch.exception.nr == DB_VECTOR &&
		    (vcpu->arch.dr7 & DR7_GD)) {
			vcpu->arch.dr7 &= ~DR7_GD;
			kvm_update_dr7(vcpu);
		}

		kvm_x86_ops->queue_exception(vcpu, vcpu->arch.exception.nr,
					  vcpu->arch.exception.has_error_code,
					  vcpu->arch.exception.error_code,
					  vcpu->arch.exception.reinject);
		return 0;
	}

	if (vcpu->arch.nmi_injected) {
		kvm_x86_ops->set_nmi(vcpu);
		return 0;
	}

	if (vcpu->arch.interrupt.pending) {
		kvm_x86_ops->set_irq(vcpu);
		return 0;
	}

	if (is_guest_mode(vcpu) && kvm_x86_ops->check_nested_events) {
		r = kvm_x86_ops->check_nested_events(vcpu, req_int_win);
		if (r != 0)
			return r;
	}

	/* try to inject new event if pending */
	if (vcpu->arch.smi_pending && !is_smm(vcpu)) {
		vcpu->arch.smi_pending = false;
		enter_smm(vcpu);
	} else if (vcpu->arch.nmi_pending && kvm_x86_ops->nmi_allowed(vcpu)) {
		--vcpu->arch.nmi_pending;
		vcpu->arch.nmi_injected = true;
		kvm_x86_ops->set_nmi(vcpu);
	} else if (kvm_cpu_has_injectable_intr(vcpu)) {
		/*
		 * Because interrupts can be injected asynchronously, we are
		 * calling check_nested_events again here to avoid a race condition.
		 * See https://lkml.org/lkml/2014/7/2/60 for discussion about this
		 * proposal and current concerns.  Perhaps we should be setting
		 * GVM_REQ_EVENT only on certain events and not unconditionally?
		 */
		if (is_guest_mode(vcpu) && kvm_x86_ops->check_nested_events) {
			r = kvm_x86_ops->check_nested_events(vcpu, req_int_win);
			if (r != 0)
				return r;
		}
		if (kvm_x86_ops->interrupt_allowed(vcpu)) {
			kvm_queue_interrupt(vcpu, kvm_cpu_get_interrupt(vcpu),
					    false);
			kvm_x86_ops->set_irq(vcpu);
		}
	}

	return 0;
}

static void process_nmi(struct kvm_vcpu *vcpu)
{
	unsigned limit = 2;

	/*
	 * x86 is limited to one NMI running, and one NMI pending after it.
	 * If an NMI is already in progress, limit further NMIs to just one.
	 * Otherwise, allow two (and we'll inject the first one immediately).
	 */
	if (kvm_x86_ops->get_nmi_mask(vcpu) || vcpu->arch.nmi_injected)
		limit = 1;

	vcpu->arch.nmi_pending += atomic_xchg(&vcpu->arch.nmi_queued, 0);
	vcpu->arch.nmi_pending = min(vcpu->arch.nmi_pending, limit);
	kvm_make_request(GVM_REQ_EVENT, vcpu);
}

#define put_smstate(type, buf, offset, val)			  \
	*(type *)((buf) + (offset) - 0x7e00) = val

static u32 enter_smm_get_segment_flags(struct kvm_segment *seg)
{
	u32 flags = 0;
	flags |= seg->g       << 23;
	flags |= seg->db      << 22;
	flags |= seg->l       << 21;
	flags |= seg->avl     << 20;
	flags |= seg->present << 15;
	flags |= seg->dpl     << 13;
	flags |= seg->s       << 12;
	flags |= seg->type    << 8;
	return flags;
}

static void enter_smm_save_seg_32(struct kvm_vcpu *vcpu, char *buf, int n)
{
	struct kvm_segment seg;
	int offset;

	kvm_get_segment(vcpu, &seg, n);
	put_smstate(u32, buf, 0x7fa8 + n * 4, seg.selector);

	if (n < 3)
		offset = 0x7f84 + n * 12;
	else
		offset = 0x7f2c + (n - 3) * 12;

	put_smstate(u32, buf, offset + 8, seg.base);
	put_smstate(u32, buf, offset + 4, seg.limit);
	put_smstate(u32, buf, offset, enter_smm_get_segment_flags(&seg));
}

#ifdef CONFIG_X86_64
static void enter_smm_save_seg_64(struct kvm_vcpu *vcpu, char *buf, int n)
{
	struct kvm_segment seg;
	int offset;
	u16 flags;

	kvm_get_segment(vcpu, &seg, n);
	offset = 0x7e00 + n * 16;

	flags = enter_smm_get_segment_flags(&seg) >> 8;
	put_smstate(u16, buf, offset, seg.selector);
	put_smstate(u16, buf, offset + 2, flags);
	put_smstate(u32, buf, offset + 4, seg.limit);
	put_smstate(u64, buf, offset + 8, seg.base);
}
#endif

static void enter_smm_save_state_32(struct kvm_vcpu *vcpu, char *buf)
{
	struct desc_ptr dt;
	struct kvm_segment seg;
	size_t val;
	int i;

	put_smstate(u32, buf, 0x7ffc, kvm_read_cr0(vcpu));
	put_smstate(u32, buf, 0x7ff8, kvm_read_cr3(vcpu));
	put_smstate(u32, buf, 0x7ff4, kvm_get_rflags(vcpu));
	put_smstate(u32, buf, 0x7ff0, kvm_rip_read(vcpu));

	for (i = 0; i < 8; i++)
		put_smstate(u32, buf, 0x7fd0 + i * 4, kvm_register_read(vcpu, i));

	kvm_get_dr(vcpu, 6, &val);
	put_smstate(u32, buf, 0x7fcc, (u32)val);
	kvm_get_dr(vcpu, 7, &val);
	put_smstate(u32, buf, 0x7fc8, (u32)val);

	kvm_get_segment(vcpu, &seg, VCPU_SREG_TR);
	put_smstate(u32, buf, 0x7fc4, seg.selector);
	put_smstate(u32, buf, 0x7f64, seg.base);
	put_smstate(u32, buf, 0x7f60, seg.limit);
	put_smstate(u32, buf, 0x7f5c, enter_smm_get_segment_flags(&seg));

	kvm_get_segment(vcpu, &seg, VCPU_SREG_LDTR);
	put_smstate(u32, buf, 0x7fc0, seg.selector);
	put_smstate(u32, buf, 0x7f80, seg.base);
	put_smstate(u32, buf, 0x7f7c, seg.limit);
	put_smstate(u32, buf, 0x7f78, enter_smm_get_segment_flags(&seg));

	kvm_x86_ops->get_gdt(vcpu, &dt);
	put_smstate(u32, buf, 0x7f74, dt.address);
	put_smstate(u32, buf, 0x7f70, dt.size);

	kvm_x86_ops->get_idt(vcpu, &dt);
	put_smstate(u32, buf, 0x7f58, dt.address);
	put_smstate(u32, buf, 0x7f54, dt.size);

	for (i = 0; i < 6; i++)
		enter_smm_save_seg_32(vcpu, buf, i);

	put_smstate(u32, buf, 0x7f14, kvm_read_cr4(vcpu));

	/* revision id */
	put_smstate(u32, buf, 0x7efc, 0x00020000);
	put_smstate(u32, buf, 0x7ef8, vcpu->arch.smbase);
}

static void enter_smm_save_state_64(struct kvm_vcpu *vcpu, char *buf)
{
#ifdef CONFIG_X86_64
	struct desc_ptr dt;
	struct kvm_segment seg;
	size_t val;
	int i;

	for (i = 0; i < 16; i++)
		put_smstate(u64, buf, 0x7ff8 - i * 8, kvm_register_read(vcpu, i));

	put_smstate(u64, buf, 0x7f78, kvm_rip_read(vcpu));
	put_smstate(u32, buf, 0x7f70, kvm_get_rflags(vcpu));

	kvm_get_dr(vcpu, 6, &val);
	put_smstate(u64, buf, 0x7f68, val);
	kvm_get_dr(vcpu, 7, &val);
	put_smstate(u64, buf, 0x7f60, val);

	put_smstate(u64, buf, 0x7f58, kvm_read_cr0(vcpu));
	put_smstate(u64, buf, 0x7f50, kvm_read_cr3(vcpu));
	put_smstate(u64, buf, 0x7f48, kvm_read_cr4(vcpu));

	put_smstate(u32, buf, 0x7f00, vcpu->arch.smbase);

	/* revision id */
	put_smstate(u32, buf, 0x7efc, 0x00020064);

	put_smstate(u64, buf, 0x7ed0, vcpu->arch.efer);

	kvm_get_segment(vcpu, &seg, VCPU_SREG_TR);
	put_smstate(u16, buf, 0x7e90, seg.selector);
	put_smstate(u16, buf, 0x7e92, enter_smm_get_segment_flags(&seg) >> 8);
	put_smstate(u32, buf, 0x7e94, seg.limit);
	put_smstate(u64, buf, 0x7e98, seg.base);

	kvm_x86_ops->get_idt(vcpu, &dt);
	put_smstate(u32, buf, 0x7e84, dt.size);
	put_smstate(u64, buf, 0x7e88, dt.address);

	kvm_get_segment(vcpu, &seg, VCPU_SREG_LDTR);
	put_smstate(u16, buf, 0x7e70, seg.selector);
	put_smstate(u16, buf, 0x7e72, enter_smm_get_segment_flags(&seg) >> 8);
	put_smstate(u32, buf, 0x7e74, seg.limit);
	put_smstate(u64, buf, 0x7e78, seg.base);

	kvm_x86_ops->get_gdt(vcpu, &dt);
	put_smstate(u32, buf, 0x7e64, dt.size);
	put_smstate(u64, buf, 0x7e68, dt.address);

	for (i = 0; i < 6; i++)
		enter_smm_save_seg_64(vcpu, buf, i);
#else
	WARN_ON_ONCE(1);
#endif
}

static void enter_smm(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ds;
	struct desc_ptr dt;
	char buf[512];
	u32 cr0;

	vcpu->arch.hflags |= HF_SMM_MASK;
	memset(buf, 0, 512);
	if (guest_cpuid_has_longmode(vcpu))
		enter_smm_save_state_64(vcpu, buf);
	else
		enter_smm_save_state_32(vcpu, buf);

	kvm_vcpu_write_guest(vcpu, vcpu->arch.smbase + 0xfe00, buf, sizeof(buf));

	if (kvm_x86_ops->get_nmi_mask(vcpu))
		vcpu->arch.hflags |= HF_SMM_INSIDE_NMI_MASK;
	else
		kvm_x86_ops->set_nmi_mask(vcpu, true);

	kvm_set_rflags(vcpu, X86_EFLAGS_FIXED);
	kvm_rip_write(vcpu, 0x8000);

	cr0 = vcpu->arch.cr0 & ~(X86_CR0_PE | X86_CR0_EM | X86_CR0_TS | X86_CR0_PG);
	kvm_x86_ops->set_cr0(vcpu, cr0);
	vcpu->arch.cr0 = cr0;

	kvm_x86_ops->set_cr4(vcpu, 0);

	/* Undocumented: IDT limit is set to zero on entry to SMM.  */
	dt.address = dt.size = 0;
	kvm_x86_ops->set_idt(vcpu, &dt);

	__kvm_set_dr(vcpu, 7, DR7_FIXED_1);

	cs.selector = (vcpu->arch.smbase >> 4) & 0xffff;
	cs.base = vcpu->arch.smbase;

	ds.selector = 0;
	ds.base = 0;

	cs.limit    = ds.limit = 0xffffffff;
	cs.type     = ds.type = 0x3;
	cs.dpl      = ds.dpl = 0;
	cs.db       = ds.db = 0;
	cs.s        = ds.s = 1;
	cs.l        = ds.l = 0;
	cs.g        = ds.g = 1;
	cs.avl      = ds.avl = 0;
	cs.present  = ds.present = 1;
	cs.unusable = ds.unusable = 0;
	cs.padding  = ds.padding = 0;

	kvm_set_segment(vcpu, &cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &ds, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &ds, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &ds, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &ds, VCPU_SREG_SS);

	if (guest_cpuid_has_longmode(vcpu))
		kvm_x86_ops->set_efer(vcpu, 0);

	kvm_update_cpuid(vcpu);
	kvm_mmu_reset_context(vcpu);
}

static void process_smi(struct kvm_vcpu *vcpu)
{
	vcpu->arch.smi_pending = true;
	kvm_make_request(GVM_REQ_EVENT, vcpu);
}

void kvm_make_scan_ioapic_request(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, GVM_REQ_SCAN_IOAPIC);
}

static void vcpu_scan_ioapic(struct kvm_vcpu *vcpu)
{
	u64 eoi_exit_bitmap[4];

	if (!kvm_apic_hw_enabled(vcpu->arch.apic))
		return;

	bitmap_zero(vcpu->arch.ioapic_handled_vectors, 256);

	kvm_ioapic_scan_entry(vcpu, vcpu->arch.ioapic_handled_vectors);
	bitmap_copy((ulong *)eoi_exit_bitmap, vcpu->arch.ioapic_handled_vectors, 256);
	kvm_x86_ops->load_eoi_exitmap(vcpu, eoi_exit_bitmap);
}

static void kvm_vcpu_flush_tlb(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.tlb_flush;
	kvm_x86_ops->tlb_flush(vcpu);
}

void kvm_vcpu_reload_apic_access_page(struct kvm_vcpu *vcpu)
{
	pfn_t pfn = 0;

	if (!lapic_in_kernel(vcpu))
		return;

	if (!kvm_x86_ops->set_apic_access_page_addr)
		return;

	pfn = gfn_to_pfn(vcpu->kvm, APIC_DEFAULT_PHYS_BASE >> PAGE_SHIFT);
	if (is_error_noslot_pfn(pfn))
		return;
	kvm_x86_ops->set_apic_access_page_addr(vcpu, pfn << PAGE_SHIFT);

	/*
	 * Do not pin apic access page in memory, the MMU notifier
	 * will call us again if it is migrated or swapped out.
	 */
	//put_page(page);
}

void kvm_arch_mmu_notifier_invalidate_page(struct kvm *kvm,
					   size_t address)
{
	/*
	 * The physical address of apic access page is stored in the VMCS.
	 * Update it when it becomes invalid.
	 */
	if (address == gfn_to_hva(kvm, APIC_DEFAULT_PHYS_BASE >> PAGE_SHIFT))
		kvm_make_all_cpus_request(kvm, GVM_REQ_APIC_PAGE_RELOAD);
}

//#define HOST_STAT_DEBUG
/*
 * A useful tool to check whether host state remains the same across
 * host->guest->host switches. In theory, host state should be saved/restored
 * only when it is subject to change. However, without souce code and
 * document, you never know. When something goes terribly wrong, this tool
 * can help check whether it is caused by incomplete host stat restore.
 */
#ifdef HOST_STAT_DEBUG
#include <intrin.h>
struct host_stat {
	struct desc_ptr gdt;
	struct desc_ptr idt;
	u16 cs_sel;
	u16 ss_sel;
	u16 ds_sel;
	u16 es_sel;
	u16 fs_sel;
	u16 gs_sel;
	u16 ldt_sel;
	u16 tr_sel;
	struct desc_struct cs;
	struct desc_struct ss;
	struct desc_struct ds;
	struct desc_struct es;
	struct desc_struct fs;
	struct desc_struct gs;
	struct desc_struct ldt;
	struct desc_struct tr;
	u64 fs_base;
	u64 gs_base;
	u64 kernel_gs_base;
	u64 cr0;
	u64 cr2;
	u64 cr3;
	u64 cr4;
	u64 cr8;
	u64 efer;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sf_mask;
	u64 sysenter_cs;
	u64 sysenter_eip;
	u64 sysenter_esp;
};

static void save_host_stat_full(struct host_stat *hs)
{
	struct desc_struct *gdt;

	_sgdt(&hs->gdt);
	__sidt(&hs->idt);

	savesegment(cs, hs->ds_sel);
	savesegment(ss, hs->ds_sel);
	savesegment(ds, hs->ds_sel);
	savesegment(es, hs->es_sel);
	savesegment(fs, hs->fs_sel);
	savesegment(gs, hs->gs_sel);
	hs->ldt_sel = gvm_read_ldt();
	hs->tr_sel = gvm_read_tr();

	gdt = (struct desc_struct *)hs->gdt.address;
	hs->cs = gdt[hs->cs_sel >> 3];
	hs->ss = gdt[hs->ss_sel >> 3];
	hs->ds = gdt[hs->ds_sel >> 3];
	hs->es = gdt[hs->es_sel >> 3];
	hs->fs = gdt[hs->fs_sel >> 3];
	hs->gs = gdt[hs->gs_sel >> 3];
	hs->ldt = gdt[hs->ldt_sel >> 3];
	hs->tr = gdt[hs->tr_sel >> 3];

	hs->fs_base = __readmsr(MSR_FS_BASE);
	hs->gs_base = __readmsr(MSR_GS_BASE);
	hs->kernel_gs_base = __readmsr(MSR_KERNEL_GS_BASE);

	hs->cr0 = __readcr0();
	hs->cr2 = __readcr2();
	hs->cr3 = __readcr3();
	hs->cr4 = __readcr4();
	hs->cr8 = __readcr8();

	hs->efer = __readmsr(MSR_EFER);
	hs->star = __readmsr(MSR_STAR);
	hs->lstar = __readmsr(MSR_LSTAR);
	hs->cstar = __readmsr(MSR_CSTAR);
	hs->sf_mask = __readmsr(MSR_SYSCALL_MASK);

	hs->sysenter_cs = __readmsr(MSR_IA32_SYSENTER_CS);
	hs->sysenter_eip = __readmsr(MSR_IA32_SYSENTER_EIP);
	hs->sysenter_esp = __readmsr(MSR_IA32_SYSENTER_ESP);
}

static int check_host_stat(struct host_stat *a, struct host_stat *b)
{
	return 0;
}
#endif

/*
 * Returns 1 to let vcpu_run() continue the guest execution loop without
 * exiting to the userspace.  Otherwise, the value will be returned to the
 * userspace.
 */
static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	int r;
	bool req_int_win =
		dm_request_for_irq_injection(vcpu) &&
		kvm_cpu_accept_dm_intr(vcpu);

	bool req_immediate_exit = false;
#ifdef HOST_STAT_DEBUG
	struct host_stat *enter = kzalloc(sizeof(struct host_stat), GFP_KERNEL);
	struct host_stat *exit = kzalloc(sizeof(struct host_stat), GFP_KERNEL);
#endif

	if (vcpu->requests) {
		if (kvm_check_request(GVM_REQ_MMU_RELOAD, vcpu))
			kvm_mmu_unload(vcpu);
		if (kvm_check_request(GVM_REQ_MMU_SYNC, vcpu))
			kvm_mmu_sync_roots(vcpu);
		if (kvm_check_request(GVM_REQ_TLB_FLUSH, vcpu))
			kvm_vcpu_flush_tlb(vcpu);
		if (kvm_check_request(GVM_REQ_REPORT_TPR_ACCESS, vcpu)) {
			vcpu->run->exit_reason = GVM_EXIT_TPR_ACCESS;
			r = 0;
			goto out;
		}
		if (kvm_check_request(GVM_REQ_TRIPLE_FAULT, vcpu)) {
			vcpu->run->exit_reason = GVM_EXIT_SHUTDOWN;
			r = 0;
			goto out;
		}
		if (kvm_check_request(GVM_REQ_SMI, vcpu))
			process_smi(vcpu);
		if (kvm_check_request(GVM_REQ_NMI, vcpu))
			process_nmi(vcpu);
#if 0
		if (kvm_check_request(GVM_REQ_PMU, vcpu))
			kvm_pmu_handle_event(vcpu);
		if (kvm_check_request(GVM_REQ_PMI, vcpu))
			kvm_pmu_deliver_pmi(vcpu);
#endif
		if (kvm_check_request(GVM_REQ_SCAN_IOAPIC, vcpu))
			vcpu_scan_ioapic(vcpu);
		if (kvm_check_request(GVM_REQ_APIC_PAGE_RELOAD, vcpu))
			kvm_vcpu_reload_apic_access_page(vcpu);
	}

	/*
	 * GVM_REQ_EVENT is not set when posted interrupts are set by
	 * VT-d hardware, so we have to update RVI unconditionally.
	 */
	if (kvm_lapic_enabled(vcpu)) {
		/*
		 * Update architecture specific hints for APIC
		 * virtual interrupt delivery.
		 */
		if (vcpu->arch.apicv_active)
			kvm_x86_ops->hwapic_irr_update(vcpu,
				kvm_lapic_find_highest_irr(vcpu));
	}

	if (kvm_check_request(GVM_REQ_EVENT, vcpu) || req_int_win) {
		kvm_apic_accept_events(vcpu);
		if (vcpu->arch.mp_state == GVM_MP_STATE_INIT_RECEIVED) {
			r = 1;
			goto out;
		}

		if (inject_pending_event(vcpu, req_int_win) != 0)
			req_immediate_exit = true;
		else {
			/* Enable NMI/IRQ window open exits if needed.
			 *
			 * SMIs have two cases: 1) they can be nested, and
			 * then there is nothing to do here because RSM will
			 * cause a vmexit anyway; 2) or the SMI can be pending
			 * because inject_pending_event has completed the
			 * injection of an IRQ or NMI from the previous vmexit,
			 * and then we request an immediate exit to inject the SMI.
			 */
			if (vcpu->arch.smi_pending && !is_smm(vcpu))
				req_immediate_exit = true;
			if (vcpu->arch.nmi_pending)
				kvm_x86_ops->enable_nmi_window(vcpu);
			if (kvm_cpu_has_injectable_intr(vcpu) || req_int_win)
				kvm_x86_ops->enable_irq_window(vcpu);
		}

		if (kvm_lapic_enabled(vcpu)) {
			update_cr8_intercept(vcpu);
			kvm_lapic_sync_to_vapic(vcpu);
		}
	}

	r = kvm_mmu_reload(vcpu);
	if (unlikely(r)) {
		goto cancel_injection;
	}

	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);

	local_irq_disable();
#ifdef HOST_STAT_DEBUG
	save_host_stat_full(enter);
#endif
	vcpu->mode = IN_GUEST_MODE;
	vcpu->cpu = smp_processor_id();

	/*
	 * We should set ->mode before check ->requests,
	 * Please see the comment in kvm_make_all_cpus_request.
	 * This also orders the write to mode from any reads
	 * to the page tables done while the VCPU is running.
	 * Please see the comment in kvm_flush_remote_tlbs.
	 */
	smp_mb();

	if (vcpu->mode == EXITING_GUEST_MODE || vcpu->requests) {
		vcpu->mode = OUTSIDE_GUEST_MODE;
		smp_wmb();
		local_irq_enable();
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
		r = 1;
		goto cancel_injection;
	}

	kvm_load_guest_xcr0(vcpu);

	if (req_immediate_exit) {
		kvm_make_request(GVM_REQ_EVENT, vcpu);
		smp_send_reschedule(vcpu->cpu);
	}

	if (unlikely(vcpu->arch.switch_db_regs)) {
		set_debugreg(0, 7);
		set_debugreg(vcpu->arch.eff_db[0], 0);
		set_debugreg(vcpu->arch.eff_db[1], 1);
		set_debugreg(vcpu->arch.eff_db[2], 2);
		set_debugreg(vcpu->arch.eff_db[3], 3);
		set_debugreg(vcpu->arch.dr6, 6);
		vcpu->arch.switch_db_regs &= ~GVM_DEBUGREG_RELOAD;
	}

	kvm_x86_ops->run(vcpu);

	/*
	 * Do this here before restoring debug registers on the host.  And
	 * since we do this before handling the vmexit, a DR access vmexit
	 * can (a) read the correct value of the debug registers, (b) set
	 * GVM_DEBUGREG_WONT_EXIT again.
	 */
	if (unlikely(vcpu->arch.switch_db_regs & GVM_DEBUGREG_WONT_EXIT)) {
		WARN_ON(vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP);
		kvm_x86_ops->sync_dirty_debug_regs(vcpu);
		kvm_update_dr0123(vcpu);
		kvm_update_dr6(vcpu);
		kvm_update_dr7(vcpu);
		vcpu->arch.switch_db_regs &= ~GVM_DEBUGREG_RELOAD;
	}

#if 0
	/*
	 * If the guest has used debug registers, at least dr7
	 * will be disabled while returning to the host.
	 * If we don't have active breakpoints in the host, we don't
	 * care about the messed up debug address registers. But if
	 * we have some of them active, restore the old state.
	 */
	if (hw_breakpoint_active())
		hw_breakpoint_restore();
#endif

	vcpu->arch.last_guest_tsc = kvm_read_l1_tsc(vcpu, rdtsc());

	//Set CPU to -1 since we don't know when we got scheduled to another
	//cpu by Windows scheduler.
	vcpu->cpu = -1;
	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();

	kvm_put_guest_xcr0(vcpu);
	kvm_x86_ops->vcpu_put(vcpu);

#ifdef HOST_STAT_DEBUG
	save_host_stat_full(exit);
	BUG_ON(check_host_stat(enter, exit));
#endif
	kvm_x86_ops->handle_external_intr(vcpu);

	++vcpu->stat.exits;

	local_irq_enable();

	vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	if (vcpu->arch.apic_attention)
		kvm_lapic_sync_from_vapic(vcpu);

	r = kvm_x86_ops->handle_exit(vcpu);
	return r;

cancel_injection:
	kvm_x86_ops->cancel_injection(vcpu);
	if ((vcpu->arch.apic_attention))
		kvm_lapic_sync_from_vapic(vcpu);
out:
	return r;
}

static inline int vcpu_block(struct kvm *kvm, struct kvm_vcpu *vcpu)
{
	if (!kvm_arch_vcpu_runnable(vcpu)) {
		srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
		kvm_vcpu_block(vcpu);
		vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);

		if (!kvm_check_request(GVM_REQ_UNHALT, vcpu))
			return 1;
	}

	kvm_apic_accept_events(vcpu);
	switch(vcpu->arch.mp_state) {
	case GVM_MP_STATE_HALTED:
		vcpu->arch.mp_state =
			GVM_MP_STATE_RUNNABLE;
	case GVM_MP_STATE_RUNNABLE:
		break;
	case GVM_MP_STATE_INIT_RECEIVED:
		break;
	default:
		return -EINTR;
		break;
	}
	return 1;
}

static inline bool kvm_vcpu_running(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.mp_state == GVM_MP_STATE_RUNNABLE);
}

static int vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm *kvm = vcpu->kvm;

	vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);

	for (;;) {
		if (test_and_clear_bit(0, (size_t *)&vcpu->run->user_event_pending)) {
			r = 0;
			vcpu->run->exit_reason = GVM_EXIT_INTR;
			break;
		}

		if (kvm_vcpu_running(vcpu)) {
			r = vcpu_enter_guest(vcpu);
		} else {
			r = vcpu_block(kvm, vcpu);
		}

		if (r <= 0)
			break;

		clear_bit(GVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu) &&
			kvm_vcpu_ready_for_interrupt_injection(vcpu)) {
			r = 0;
			vcpu->run->exit_reason = GVM_EXIT_IRQ_WINDOW_OPEN;
			++vcpu->stat.request_irq_exits;
			break;
		}
	}

	srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);

	return r;
}

static inline int complete_emulated_io(struct kvm_vcpu *vcpu)
{
	int r;
	vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	r = emulate_instruction(vcpu, EMULTYPE_NO_DECODE);
	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
	if (r != EMULATE_DONE)
		return 0;
	return 1;
}

static int complete_emulated_pio(struct kvm_vcpu *vcpu)
{
	BUG_ON(!vcpu->arch.pio.count);

	return complete_emulated_io(vcpu);
}

/*
 * Implements the following, as a state machine:
 *
 * read:
 *   for each fragment
 *     for each mmio piece in the fragment
 *       write gpa, len
 *       exit
 *       copy data
 *   execute insn
 *
 * write:
 *   for each fragment
 *     for each mmio piece in the fragment
 *       write gpa, len
 *       copy data
 *       exit
 */
static int complete_emulated_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct kvm_mmio_fragment *frag;
	unsigned len;
	char *__data;

	BUG_ON(!vcpu->mmio_needed);

	/* Complete previous fragment */
	frag = &vcpu->mmio_fragments[vcpu->mmio_cur_fragment];
	len = min(8u, frag->len);
	if (!vcpu->mmio_is_write)
		memcpy(frag->data, run->mmio.data, len);

	if (frag->len <= 8) {
		/* Switch to the next fragment. */
		frag++;
		vcpu->mmio_cur_fragment++;
	} else {
		/* Go forward to the next mmio piece. */
		__data = frag->data;
		__data += len;
		frag->data = __data;
		frag->gpa += len;
		frag->len -= len;
	}

	if (vcpu->mmio_cur_fragment >= vcpu->mmio_nr_fragments) {
		vcpu->mmio_needed = 0;

		/* FIXME: return into emulator if single-stepping.  */
		if (vcpu->mmio_is_write)
			return 1;
		vcpu->mmio_read_completed = 1;
		return complete_emulated_io(vcpu);
	}

	run->exit_reason = GVM_EXIT_MMIO;
	run->mmio.phys_addr = frag->gpa;
	if (vcpu->mmio_is_write)
		memcpy(run->mmio.data, frag->data, min(8u, frag->len));
	run->mmio.len = min(8u, frag->len);
	run->mmio.is_write = vcpu->mmio_is_write;
	vcpu->arch.complete_userspace_io = complete_emulated_mmio;
	return 0;
}


int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;

	if (unlikely(vcpu->arch.mp_state == GVM_MP_STATE_UNINITIALIZED)) {
		kvm_vcpu_block(vcpu);
		kvm_apic_accept_events(vcpu);
		clear_bit(GVM_REQ_UNHALT, &vcpu->requests);
		r = -EAGAIN;
		goto out;
	}

	/* re-sync apic's tpr */
	if (!lapic_in_kernel(vcpu)) {
		if (kvm_set_cr8(vcpu, kvm_run->cr8) != 0) {
			r = -EINVAL;
			goto out;
		}
	}

	if (unlikely(vcpu->arch.complete_userspace_io)) {
		int (*cui)(struct kvm_vcpu *) = vcpu->arch.complete_userspace_io;
		vcpu->arch.complete_userspace_io = NULL;
		r = cui(vcpu);
		if (r <= 0)
			goto out;
	} else
		WARN_ON(vcpu->arch.pio.count || vcpu->mmio_needed);

	r = vcpu_run(vcpu);

out:
	post_kvm_run_save(vcpu);
	return r;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	if (vcpu->arch.emulate_regs_need_sync_to_vcpu) {
		/*
		 * We are here if userspace calls get_regs() in the middle of
		 * instruction emulation. Registers state needs to be copied
		 * back from emulation context to vcpu. Userspace shouldn't do
		 * that usually, but some bad designed PV devices (vmware
		 * backdoor interface) need this to work
		 */
		emulator_writeback_register_cache(&vcpu->arch.emulate_ctxt);
		vcpu->arch.emulate_regs_need_sync_to_vcpu = false;
	}
	regs->rax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	regs->rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	regs->rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	regs->rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	regs->rsi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	regs->rdi = kvm_register_read(vcpu, VCPU_REGS_RDI);
	regs->rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	regs->rbp = kvm_register_read(vcpu, VCPU_REGS_RBP);
#ifdef CONFIG_X86_64
	regs->r8 = kvm_register_read(vcpu, VCPU_REGS_R8);
	regs->r9 = kvm_register_read(vcpu, VCPU_REGS_R9);
	regs->r10 = kvm_register_read(vcpu, VCPU_REGS_R10);
	regs->r11 = kvm_register_read(vcpu, VCPU_REGS_R11);
	regs->r12 = kvm_register_read(vcpu, VCPU_REGS_R12);
	regs->r13 = kvm_register_read(vcpu, VCPU_REGS_R13);
	regs->r14 = kvm_register_read(vcpu, VCPU_REGS_R14);
	regs->r15 = kvm_register_read(vcpu, VCPU_REGS_R15);
#endif

	regs->rip = kvm_rip_read(vcpu);
	regs->rflags = kvm_get_rflags(vcpu);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	vcpu->arch.emulate_regs_need_sync_from_vcpu = true;
	vcpu->arch.emulate_regs_need_sync_to_vcpu = false;

	kvm_register_write(vcpu, VCPU_REGS_RAX, regs->rax);
	kvm_register_write(vcpu, VCPU_REGS_RBX, regs->rbx);
	kvm_register_write(vcpu, VCPU_REGS_RCX, regs->rcx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, regs->rdx);
	kvm_register_write(vcpu, VCPU_REGS_RSI, regs->rsi);
	kvm_register_write(vcpu, VCPU_REGS_RDI, regs->rdi);
	kvm_register_write(vcpu, VCPU_REGS_RSP, regs->rsp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, regs->rbp);
#ifdef CONFIG_X86_64
	kvm_register_write(vcpu, VCPU_REGS_R8, regs->r8);
	kvm_register_write(vcpu, VCPU_REGS_R9, regs->r9);
	kvm_register_write(vcpu, VCPU_REGS_R10, regs->r10);
	kvm_register_write(vcpu, VCPU_REGS_R11, regs->r11);
	kvm_register_write(vcpu, VCPU_REGS_R12, regs->r12);
	kvm_register_write(vcpu, VCPU_REGS_R13, regs->r13);
	kvm_register_write(vcpu, VCPU_REGS_R14, regs->r14);
	kvm_register_write(vcpu, VCPU_REGS_R15, regs->r15);
#endif

	kvm_rip_write(vcpu, regs->rip);
	kvm_set_rflags(vcpu, regs->rflags);

	vcpu->arch.exception.pending = false;

	kvm_make_request(GVM_REQ_EVENT, vcpu);

	return 0;
}

void kvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	struct kvm_segment cs;

	kvm_get_segment(vcpu, &cs, VCPU_SREG_CS);
	*db = cs.db;
	*l = cs.l;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	struct desc_ptr dt;

	kvm_get_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_get_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_get_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_get_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_get_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_get_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_get_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	kvm_x86_ops->get_idt(vcpu, &dt);
	sregs->idt.limit = dt.size;
	sregs->idt.base = dt.address;
	kvm_x86_ops->get_gdt(vcpu, &dt);
	sregs->gdt.limit = dt.size;
	sregs->gdt.base = dt.address;

	sregs->cr0 = kvm_read_cr0(vcpu);
	sregs->cr2 = vcpu->arch.cr2;
	sregs->cr3 = kvm_read_cr3(vcpu);
	sregs->cr4 = kvm_read_cr4(vcpu);
	sregs->cr8 = kvm_get_cr8(vcpu);
	sregs->efer = vcpu->arch.efer;
	sregs->apic_base = kvm_get_apic_base(vcpu);

	memset(sregs->interrupt_bitmap, 0, sizeof sregs->interrupt_bitmap);

	if (vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft)
		set_bit(vcpu->arch.interrupt.nr,
			(size_t *)sregs->interrupt_bitmap);

	return 0;
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	kvm_apic_accept_events(vcpu);
	mp_state->mp_state = vcpu->arch.mp_state;

	return 0;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	if (!lapic_in_kernel(vcpu) &&
	    mp_state->mp_state != GVM_MP_STATE_RUNNABLE)
		return -EINVAL;

	if (mp_state->mp_state == GVM_MP_STATE_SIPI_RECEIVED) {
		vcpu->arch.mp_state = GVM_MP_STATE_INIT_RECEIVED;
		set_bit(GVM_APIC_SIPI, &vcpu->arch.apic->pending_events);
	} else
		vcpu->arch.mp_state = mp_state->mp_state;
	kvm_make_request(GVM_REQ_EVENT, vcpu);
	return 0;
}

int kvm_task_switch(struct kvm_vcpu *vcpu, u16 tss_selector, int idt_index,
		    int reason, bool has_error_code, u32 error_code)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	int ret;

	init_emulate_ctxt(vcpu);

	ret = emulator_task_switch(ctxt, tss_selector, idt_index, reason,
				   has_error_code, error_code);

	if (ret)
		return EMULATE_FAIL;

	kvm_rip_write(vcpu, ctxt->eip);
	kvm_set_rflags(vcpu, ctxt->eflags);
	kvm_make_request(GVM_REQ_EVENT, vcpu);
	return EMULATE_DONE;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	struct msr_data apic_base_msr;
	int mmu_reset_needed = 0;
	int pending_vec, max_bits, idx;
	struct desc_ptr dt;

	if (!guest_cpuid_has_xsave(vcpu) && (sregs->cr4 & X86_CR4_OSXSAVE))
		return -EINVAL;

	dt.size = sregs->idt.limit;
	dt.address = sregs->idt.base;
	kvm_x86_ops->set_idt(vcpu, &dt);
	dt.size = sregs->gdt.limit;
	dt.address = sregs->gdt.base;
	kvm_x86_ops->set_gdt(vcpu, &dt);

	vcpu->arch.cr2 = sregs->cr2;
	mmu_reset_needed |= kvm_read_cr3(vcpu) != sregs->cr3;
	vcpu->arch.cr3 = sregs->cr3;
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);

	kvm_set_cr8(vcpu, sregs->cr8);

	mmu_reset_needed |= vcpu->arch.efer != sregs->efer;
	kvm_x86_ops->set_efer(vcpu, sregs->efer);
	apic_base_msr.data = sregs->apic_base;
	apic_base_msr.host_initiated = true;
	kvm_set_apic_base(vcpu, &apic_base_msr);

	mmu_reset_needed |= kvm_read_cr0(vcpu) != sregs->cr0;
	kvm_x86_ops->set_cr0(vcpu, sregs->cr0);
	vcpu->arch.cr0 = sregs->cr0;

	mmu_reset_needed |= kvm_read_cr4(vcpu) != sregs->cr4;
	kvm_x86_ops->set_cr4(vcpu, sregs->cr4);
	if (sregs->cr4 & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		kvm_update_cpuid(vcpu);

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (!is_long_mode(vcpu) && is_pae(vcpu)) {
		load_pdptrs(vcpu, vcpu->arch.walk_mmu, kvm_read_cr3(vcpu));
		mmu_reset_needed = 1;
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);

	max_bits = GVM_NR_INTERRUPTS;
	pending_vec = find_first_bit(
		(const size_t *)sregs->interrupt_bitmap, max_bits);
	if (pending_vec < max_bits) {
		kvm_queue_interrupt(vcpu, pending_vec, false);
		pr_debug("Set back pending irq %d\n", pending_vec);
	}

	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	update_cr8_intercept(vcpu);

	/* Older userspace won't unhalt the vcpu on reset. */
	if (kvm_vcpu_is_bsp(vcpu) && kvm_rip_read(vcpu) == 0xfff0 &&
	    sregs->cs.selector == 0xf000 && sregs->cs.base == 0xffff0000 &&
	    !is_protmode(vcpu))
		vcpu->arch.mp_state = GVM_MP_STATE_RUNNABLE;

	kvm_make_request(GVM_REQ_EVENT, vcpu);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	size_t rflags;
	int i, r;

	if (dbg->control & (GVM_GUESTDBG_INJECT_DB | GVM_GUESTDBG_INJECT_BP)) {
		r = -EBUSY;
		if (vcpu->arch.exception.pending)
			goto out;
		if (dbg->control & GVM_GUESTDBG_INJECT_DB)
			kvm_queue_exception(vcpu, DB_VECTOR);
		else
			kvm_queue_exception(vcpu, BP_VECTOR);
	}

	/*
	 * Read rflags as long as potentially injected trace flags are still
	 * filtered out.
	 */
	rflags = kvm_get_rflags(vcpu);

	vcpu->guest_debug = dbg->control;
	if (!(vcpu->guest_debug & GVM_GUESTDBG_ENABLE))
		vcpu->guest_debug = 0;

	if (vcpu->guest_debug & GVM_GUESTDBG_USE_HW_BP) {
		for (i = 0; i < GVM_NR_DB_REGS; ++i)
			vcpu->arch.eff_db[i] = dbg->arch.debugreg[i];
		vcpu->arch.guest_debug_dr7 = dbg->arch.debugreg[7];
	} else {
		for (i = 0; i < GVM_NR_DB_REGS; i++)
			vcpu->arch.eff_db[i] = vcpu->arch.db[i];
	}
	kvm_update_dr7(vcpu);

	if (vcpu->guest_debug & GVM_GUESTDBG_SINGLESTEP)
		vcpu->arch.singlestep_rip = kvm_rip_read(vcpu) +
			get_segment_base(vcpu, VCPU_SREG_CS);

	/*
	 * Trigger an rflags update that will inject or remove the trace
	 * flags.
	 */
	kvm_set_rflags(vcpu, rflags);

	kvm_x86_ops->update_bp_intercept(vcpu);

	r = 0;

out:

	return r;
}

/*
 * Translate a guest virtual address to a guest physical address.
 */
int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				    struct kvm_translation *tr)
{
	size_t vaddr = tr->linear_address;
	gpa_t gpa;
	int idx;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	gpa = kvm_mmu_gva_to_gpa_system(vcpu, vaddr, NULL);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	tr->physical_address = gpa;
	tr->valid = gpa != UNMAPPED_GVA;
	tr->writeable = 1;
	tr->usermode = 0;

	return 0;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	struct fxregs_state *fxsave =
			&vcpu->arch.guest_fpu.fxsave;

	memcpy(fpu->fpr, fxsave->st_space, 128);
	fpu->fcw = fxsave->cwd;
	fpu->fsw = fxsave->swd;
	fpu->ftwx = fxsave->twd;
	fpu->last_opcode = fxsave->fop;
	fpu->last_ip = fxsave->rip;
	fpu->last_dp = fxsave->rdp;
	memcpy(fpu->xmm, fxsave->xmm_space, sizeof fxsave->xmm_space);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	struct fxregs_state *fxsave =
			&vcpu->arch.guest_fpu.fxsave;

	memcpy(fxsave->st_space, fpu->fpr, 128);
	fxsave->cwd = fpu->fcw;
	fxsave->swd = fpu->fsw;
	fxsave->twd = fpu->ftwx;
	fxsave->fop = fpu->last_opcode;
	fxsave->rip = fpu->last_ip;
	fxsave->rdp = fpu->last_dp;
	memcpy(fxsave->xmm_space, fpu->xmm, sizeof fxsave->xmm_space);

	return 0;
}

static inline void fpstate_init_fxstate(struct fxregs_state *fx)
{
	fx->cwd = 0x37f;
	fx->mxcsr = 0x1f80;
}

static void fpstate_init(union fpu_state *state)
{
	memset(state, 0, PAGE_SIZE);

#if 0
	if (static_cpu_has(X86_FEATURE_XSAVES))
		fpstate_init_xstate(&state->xsave);
#endif
	fpstate_init_fxstate(&state->fxsave);
}

static void fx_init(struct kvm_vcpu *vcpu)
{
	fpstate_init(&vcpu->arch.guest_fpu);
	if (boot_cpu_has(X86_FEATURE_XSAVES))
		vcpu->arch.guest_fpu.xsave.header.xcomp_bv =
			host_xcr0 | XSTATE_COMPACTION_ENABLED;

	/*
	 * Ensure guest xcr0 is valid for loading
	 */
	vcpu->arch.xcr0 = XFEATURE_MASK_FP;

	vcpu->arch.cr0 |= X86_CR0_ET;
}

/*
 * These must be called with preempt disabled. Returns
 * 'true' if the FPU state is still intact and we can
 * keep registers active.
 *
 * The legacy FNSAVE instruction cleared all FPU state
 * unconditionally, so registers are essentially destroyed.
 * Modern FPU state can be kept in registers, if there are
 * no pending FP exceptions.
 */
static inline void fpu_fxsave(union fpu_state *fpu)
{
#if 0
	if (likely(use_xsave())) {
		copy_xregs_to_kernel(&fpu->state.xsave);
	}
#endif

#ifdef _WIN64
	_fxsave64(&fpu->fxsave);
#else
	_fxsave(&fpu->fxsave);
#endif
}

static inline void fpu_fxstore(union fpu_state *fpu)
{
#if 0
	if (use_xsave()) {
		copy_kernel_to_xregs(&fpstate->xsave, mask);
		return;
	}
#endif
#ifdef _WIN64
	_fxrstor64(&fpu->fxsave);
#else
	_fxrstor(&fpu->fxsave);
#endif
}

void kvm_load_guest_fpu(struct kvm_vcpu *vcpu)
{
	fpu_fxsave(&vcpu->arch.host_fpu);
	fpu_fxstore(&vcpu->arch.guest_fpu);
}

void kvm_save_guest_fpu(struct kvm_vcpu *vcpu)
{
	fpu_fxsave(&vcpu->arch.guest_fpu);
	fpu_fxstore(&vcpu->arch.host_fpu);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->vcpu_free(vcpu);
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm,
						unsigned int id)
{
	struct kvm_vcpu *vcpu;

	if (check_tsc_unstable() && atomic_read(&kvm->online_vcpus) != 0)
		printk_once(KERN_WARNING
		"kvm: SMP vm created on host with unstable TSC; "
		"guest TSC will not be reliable\n");

	vcpu = kvm_x86_ops->vcpu_create(kvm, id);

	return vcpu;
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	kvm_vcpu_mtrr_init(vcpu);
	kvm_vcpu_reset(vcpu, false);
	kvm_mmu_setup(vcpu);
	return 0;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
	struct msr_data msr;

	msr.data = 0x0;
	msr.index = MSR_IA32_TSC;
	msr.host_initiated = true;
	kvm_write_tsc(vcpu, &msr);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);

	kvm_x86_ops->vcpu_free(vcpu);
}

void kvm_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	vcpu->arch.hflags = 0;

	vcpu->arch.smi_pending = 0;
	atomic_set(&vcpu->arch.nmi_queued, 0);
	vcpu->arch.nmi_pending = 0;
	vcpu->arch.nmi_injected = false;
	kvm_clear_interrupt_queue(vcpu);
	kvm_clear_exception_queue(vcpu);

	memset(vcpu->arch.db, 0, sizeof(vcpu->arch.db));
	kvm_update_dr0123(vcpu);
	vcpu->arch.dr6 = DR6_INIT;
	kvm_update_dr6(vcpu);
	vcpu->arch.dr7 = DR7_FIXED_1;
	kvm_update_dr7(vcpu);

	vcpu->arch.cr2 = 0;

	kvm_make_request(GVM_REQ_EVENT, vcpu);

	if (!init_event) {
		//kvm_pmu_reset(vcpu);
		vcpu->arch.smbase = 0x30000;
	}

	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));
	vcpu->arch.regs_avail = ~0;
	vcpu->arch.regs_dirty = ~0;

	kvm_x86_ops->vcpu_reset(vcpu, init_event);
}

void kvm_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	struct kvm_segment cs;

	kvm_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs.selector = vector << 8;
	cs.base = vector << 12;
	kvm_set_segment(vcpu, &cs, VCPU_SREG_CS);
	kvm_rip_write(vcpu, 0);
}

int kvm_arch_hardware_enable(void)
{
	return kvm_x86_ops->hardware_enable();
}

void kvm_arch_hardware_disable(void)
{
	kvm_x86_ops->hardware_disable();
}

int kvm_arch_hardware_setup(void)
{
	int r;

	r = kvm_x86_ops->hardware_setup();
	if (r != 0)
		return r;

	kvm_init_msr_list();
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
	kvm_x86_ops->hardware_unsetup();
}

void kvm_arch_check_processor_compat(void *rtn)
{
	kvm_x86_ops->check_processor_compatibility(rtn);
}

bool kvm_vcpu_is_reset_bsp(struct kvm_vcpu *vcpu)
{
	return vcpu->kvm->arch.bsp_vcpu_id == vcpu->vcpu_id;
}

bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.apic_base & MSR_IA32_APICBASE_BSP) != 0;
}

int kvm_no_apic_vcpu = 1;

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm;
	int r;

	BUG_ON(vcpu->kvm == NULL);
	kvm = vcpu->kvm;

	vcpu->arch.apicv_active = kvm_x86_ops->get_enable_apicv();
	vcpu->arch.emulate_ctxt.ops = &emulate_ops;
	if (!irqchip_in_kernel(kvm) || kvm_vcpu_is_reset_bsp(vcpu))
		vcpu->arch.mp_state = GVM_MP_STATE_RUNNABLE;
	else
		vcpu->arch.mp_state = GVM_MP_STATE_UNINITIALIZED;

	vcpu->arch.pio_data = (void *)((size_t)vcpu->run + PAGE_SIZE);

	r = kvm_mmu_create(vcpu);
	if (r < 0)
		goto fail;

	if (irqchip_in_kernel(kvm)) {
		r = kvm_create_lapic(vcpu);
		if (r < 0)
			goto fail_mmu_destroy;
	} 

	fx_init(vcpu);

	vcpu->arch.ia32_tsc_adjust_msr = 0x0;

	vcpu->arch.guest_supported_xcr0 = 0;
	vcpu->arch.guest_xstate_size = XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET;

	vcpu->arch.maxphyaddr = cpuid_query_maxphyaddr(vcpu);

	vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;

	//kvm_pmu_init(vcpu);

	vcpu->arch.pending_external_vector = -1;

	return 0;

fail_mmu_destroy:
	kvm_mmu_destroy(vcpu);
fail:
	return r;
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	int idx;

	//kvm_pmu_destroy(vcpu);
	kvm_free_lapic(vcpu);
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	kvm_mmu_destroy(vcpu);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
}

int kvm_arch_init_vm(struct kvm *kvm, size_t type)
{
	if (type)
		return -EINVAL;

	INIT_HLIST_HEAD(&kvm->arch.mask_notifier_list);
	INIT_LIST_HEAD(&kvm->arch.active_mmu_pages);
	INIT_LIST_HEAD(&kvm->arch.zapped_obsolete_pages);

	/* Reserve bit 0 of irq_sources_bitmap for userspace irq source */
	set_bit(GVM_USERSPACE_IRQ_SOURCE_ID, &kvm->arch.irq_sources_bitmap);

	raw_spin_lock_init(&kvm->arch.tsc_write_lock);
	mutex_init(&kvm->arch.apic_map_lock);

	kvm_page_track_init(kvm);
	kvm_mmu_init_vm(kvm);

	if (kvm_x86_ops->vm_init)
		return kvm_x86_ops->vm_init(kvm);

	return 0;
}

static void kvm_unload_vcpu_mmu(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu);
}

static void kvm_free_vcpus(struct kvm *kvm)
{
	unsigned int i;
	struct kvm_vcpu *vcpu;

	/*
	 * Unpin any mmu pages first.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_unload_vcpu_mmu(vcpu);
	}
	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_arch_vcpu_free(vcpu);

	mutex_lock(&kvm->lock);
	for (i = 0; i < atomic_read(&kvm->online_vcpus); i++)
		kvm->vcpus[i] = NULL;

	atomic_set(&kvm->online_vcpus, 0);
	mutex_unlock(&kvm->lock);
}

int __x86_set_memory_region(struct kvm *kvm, int id, gpa_t gpa, u32 size)
{
	int i, r;
	size_t hva;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *slot, old;

	/* Called with kvm->slots_lock held.  */
	if (WARN_ON(id >= GVM_MEM_SLOTS_NUM))
		return -EINVAL;

	slot = id_to_memslot(slots, id);
	if (size) {
		if (slot->npages)
			return -EEXIST;

		/*
		 * MAP_SHARED to prevent internal slot pages from being moved
		 * by fork()/COW.
		 */
		hva = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, 0);
		if (IS_ERR((void *)hva))
			return PTR_ERR((void *)hva);
	} else {
		if (!slot->npages)
			return 0;

		hva = 0;
	}

	old = *slot;
	for (i = 0; i < GVM_ADDRESS_SPACE_NUM; i++) {
		struct kvm_userspace_memory_region m;

		m.slot = id | (i << 16);
		m.flags = 0;
		m.guest_phys_addr = gpa;
		m.userspace_addr = hva;
		m.memory_size = size;
		r = __kvm_set_memory_region(kvm, &m);
		if (r < 0)
			return r;
	}

	if (!size) {
		r = vm_munmap(old.userspace_addr, old.npages * PAGE_SIZE);
		WARN_ON(r < 0);
	}

	return 0;
}

int x86_set_memory_region(struct kvm *kvm, int id, gpa_t gpa, u32 size)
{
	int r;

	mutex_lock(&kvm->slots_lock);
	r = __x86_set_memory_region(kvm, id, gpa, size);
	mutex_unlock(&kvm->slots_lock);

	return r;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	if (IoGetCurrentProcess() == kvm->process) {
		/*
		 * Free memory regions allocated on behalf of userspace,
		 * unless the the memory map has changed due to process exit
		 * or fd copying.
		 */
		x86_set_memory_region(kvm, APIC_ACCESS_PAGE_PRIVATE_MEMSLOT, 0, 0);
		x86_set_memory_region(kvm, IDENTITY_PAGETABLE_PRIVATE_MEMSLOT, 0, 0);
		x86_set_memory_region(kvm, TSS_PRIVATE_MEMSLOT, 0, 0);
	}
	if (kvm_x86_ops->vm_destroy)
		kvm_x86_ops->vm_destroy(kvm);
	kfree(kvm->arch.vpic);
	kfree(kvm->arch.vioapic);
	kvm_free_vcpus(kvm);
	kvfree(rcu_dereference(kvm->arch.apic_map));
	kvm_mmu_uninit_vm(kvm);
	kvm_page_track_destroy(kvm);
}

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			   struct kvm_memory_slot *dont)
{
	if (!dont || free->arch.rmap != dont->arch.rmap) {
		kvfree(free->arch.rmap);
		free->arch.rmap = NULL;
	}
	kvm_page_track_free_memslot(free, dont);
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
			    size_t npages)
{
	slot->arch.rmap =
		kvm_kvzalloc(npages * sizeof(*slot->arch.rmap));
	if (!slot->arch.rmap)
		goto out_free;

	if (kvm_page_track_create_memslot(slot, npages))
		goto out_free;

	return 0;

out_free:
	kvfree(slot->arch.rmap);
	return -ENOMEM;
}

void kvm_arch_memslots_updated(struct kvm *kvm, struct kvm_memslots *slots)
{
	/*
	 * memslots->generation has been incremented.
	 * mmio generation may have reached its maximum value.
	 */
	kvm_mmu_invalidate_mmio_sptes(kvm, slots);
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				const struct kvm_userspace_memory_region *mem,
				enum kvm_mr_change change)
{
	return 0;
}

static void kvm_mmu_slot_apply_flags(struct kvm *kvm,
				     struct kvm_memory_slot *new)
{
	/* Still write protect RO slot */
	if (new->flags & GVM_MEM_READONLY) {
		kvm_mmu_slot_remove_write_access(kvm, new);
		return;
	}

	/*
	 * Call kvm_x86_ops dirty logging hooks when they are valid.
	 *
	 * kvm_x86_ops->slot_disable_log_dirty is called when:
	 *
	 *  - GVM_MR_CREATE with dirty logging is disabled
	 *  - GVM_MR_FLAGS_ONLY with dirty logging is disabled in new flag
	 *
	 * The reason is, in case of PML, we need to set D-bit for any slots
	 * with dirty logging disabled in order to eliminate unnecessary GPA
	 * logging in PML buffer (and potential PML buffer full VMEXT). This
	 * guarantees leaving PML enabled during guest's lifetime won't have
	 * any additonal overhead from PML when guest is running with dirty
	 * logging disabled for memory slots.
	 *
	 * kvm_x86_ops->slot_enable_log_dirty is called when switching new slot
	 * to dirty logging mode.
	 *
	 * If kvm_x86_ops dirty logging hooks are invalid, use write protect.
	 *
	 * In case of write protect:
	 *
	 * Write protect all pages for dirty logging.
	 *
	 * All the sptes including the large sptes which point to this
	 * slot are set to readonly. We can not create any new large
	 * spte on this slot until the end of the logging.
	 *
	 * See the comments in fast_page_fault().
	 */
	if (new->flags & GVM_MEM_LOG_DIRTY_PAGES) {
		if (kvm_x86_ops->slot_enable_log_dirty)
			kvm_x86_ops->slot_enable_log_dirty(kvm, new);
		else
			kvm_mmu_slot_remove_write_access(kvm, new);
	} else {
		if (kvm_x86_ops->slot_disable_log_dirty)
			kvm_x86_ops->slot_disable_log_dirty(kvm, new);
	}
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				const struct kvm_userspace_memory_region *mem,
				const struct kvm_memory_slot *old,
				const struct kvm_memory_slot *new,
				enum kvm_mr_change change)
{
	int nr_mmu_pages = 0;

	if (!kvm->arch.n_requested_mmu_pages)
		nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);

	if (nr_mmu_pages)
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);

	/*
	 * Dirty logging tracks sptes in 4k granularity, meaning that large
	 * sptes have to be split.  If live migration is successful, the guest
	 * in the source machine will be destroyed and large sptes will be
	 * created in the destination. However, if the guest continues to run
	 * in the source machine (for example if live migration fails), small
	 * sptes will remain around and cause bad performance.
	 *
	 * Scan sptes if dirty logging has been stopped, dropping those
	 * which can be collapsed into a single large-page spte.  Later
	 * page faults will create the large-page sptes.
	 */
	if ((change != GVM_MR_DELETE) &&
		(old->flags & GVM_MEM_LOG_DIRTY_PAGES) &&
		!(new->flags & GVM_MEM_LOG_DIRTY_PAGES))
		kvm_mmu_zap_collapsible_sptes(kvm, new);

	/*
	 * Set up write protection and/or dirty logging for the new slot.
	 *
	 * For GVM_MR_DELETE and GVM_MR_MOVE, the shadow pages of old slot have
	 * been zapped so no dirty logging staff is needed for old slot. For
	 * GVM_MR_FLAGS_ONLY, the old slot is essentially the same one as the
	 * new and it's also covered when dealing with the new slot.
	 *
	 * FIXME: const-ify all uses of struct kvm_memory_slot.
	 */
	if (change != GVM_MR_DELETE)
		kvm_mmu_slot_apply_flags(kvm, (struct kvm_memory_slot *) new);
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	kvm_mmu_invalidate_zap_all_pages(kvm);
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot)
{
	kvm_mmu_invalidate_zap_all_pages(kvm);
}

static inline bool kvm_vcpu_has_events(struct kvm_vcpu *vcpu)
{
	if (kvm_apic_has_events(vcpu))
		return true;

	if (atomic_read(&vcpu->arch.nmi_queued))
		return true;

	if (test_bit(GVM_REQ_SMI, &vcpu->requests))
		return true;

	if (kvm_arch_interrupt_allowed(vcpu) &&
	    kvm_cpu_has_interrupt(vcpu))
		return true;

	return false;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu) && kvm_x86_ops->check_nested_events)
		kvm_x86_ops->check_nested_events(vcpu, false);

	return kvm_vcpu_running(vcpu) || kvm_vcpu_has_events(vcpu);
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

int kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return kvm_x86_ops->interrupt_allowed(vcpu);
}

size_t kvm_get_linear_rip(struct kvm_vcpu *vcpu)
{
	if (is_64_bit_mode(vcpu))
		return kvm_rip_read(vcpu);
	return (u32)(get_segment_base(vcpu, VCPU_SREG_CS) +
		     kvm_rip_read(vcpu));
}

bool kvm_is_linear_rip(struct kvm_vcpu *vcpu, size_t linear_rip)
{
	return kvm_get_linear_rip(vcpu) == linear_rip;
}

size_t kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	size_t rflags;

	rflags = kvm_x86_ops->get_rflags(vcpu);
	if (vcpu->guest_debug & GVM_GUESTDBG_SINGLESTEP)
		rflags &= ~X86_EFLAGS_TF;
	return rflags;
}

static void __kvm_set_rflags(struct kvm_vcpu *vcpu, size_t rflags)
{
	if (vcpu->guest_debug & GVM_GUESTDBG_SINGLESTEP &&
	    kvm_is_linear_rip(vcpu, vcpu->arch.singlestep_rip))
		rflags |= X86_EFLAGS_TF;
	kvm_x86_ops->set_rflags(vcpu, rflags);
}

void kvm_set_rflags(struct kvm_vcpu *vcpu, size_t rflags)
{
	__kvm_set_rflags(vcpu, rflags);
	kvm_make_request(GVM_REQ_EVENT, vcpu);
}

bool kvm_vector_hashing_enabled(void)
{
	return vector_hashing;
}

