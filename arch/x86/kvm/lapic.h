/*
 * Copyright 2019 Google LLC
 */

#ifndef __KVM_X86_LAPIC_H
#define __KVM_X86_LAPIC_H

#include <kvm/iodev.h>

#include <linux/kvm_host.h>

#include <ntkrutils.h>
#include <asm/apicdef.h>
#include <asm/msr-index.h>
#include <aehd_types.h>
#include <ntkrutils.h>

#define AEHD_APIC_INIT		0
#define AEHD_APIC_SIPI		1
#define AEHD_APIC_LVT_NUM	6

#define AEHD_APIC_SHORT_MASK	0xc0000
#define AEHD_APIC_DEST_MASK	0x800

#define u32 unsigned int

struct kvm_timer {
	struct hrtimer timer;
	s64 period; 				/* unit: ns */
	u32 timer_mode;
	u32 timer_mode_mask;
	atomic_t pending;			/* accumulated triggered timers */
};

struct kvm_lapic {
	size_t base_address;
	struct kvm_io_device dev;
	struct kvm_timer lapic_timer;
	u32 divide_count;
	struct kvm_vcpu *vcpu;
	bool sw_enabled;
	bool irr_pending;
	bool lvt0_in_nmi_mode;
	/* Number of bits set in ISR. */
	s16 isr_count;
	/* The highest vector set in ISR; if -1 - invalid, must scan ISR. */
	int highest_isr_cache;
	/**
	 * APIC register page.  The layout matches the register layout seen by
	 * the guest 1:1, because it is accessed by the vmx microcode.
	 * Note: Only one register, the TPR, is used by the microcode.
	 */
	u8 *regs;
	gpa_t vapic_addr;
	struct gfn_to_hva_cache vapic_cache;
	size_t pending_events;
	unsigned int sipi_vector;
};

struct dest_map;

int kvm_create_lapic(struct kvm_vcpu *vcpu);
void kvm_free_lapic(struct kvm_vcpu *vcpu);

int kvm_apic_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu);
int kvm_get_apic_interrupt(struct kvm_vcpu *vcpu);
void kvm_apic_accept_events(struct kvm_vcpu *vcpu);
void kvm_lapic_reset(struct kvm_vcpu *vcpu, bool init_event);
u64 kvm_lapic_get_cr8(struct kvm_vcpu *vcpu);
void kvm_lapic_set_tpr(struct kvm_vcpu *vcpu, size_t cr8);
void kvm_lapic_set_eoi(struct kvm_vcpu *vcpu);
void kvm_lapic_set_base(struct kvm_vcpu *vcpu, u64 value);
u64 kvm_lapic_get_base(struct kvm_vcpu *vcpu);
void kvm_apic_set_version(struct kvm_vcpu *vcpu);
int kvm_lapic_reg_write(struct kvm_lapic *apic, u32 reg, u32 val);
int kvm_lapic_reg_read(struct kvm_lapic *apic, u32 offset, int len,
		       void *data);
bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
			   int short_hand, unsigned int dest, int dest_mode);

void __kvm_apic_update_irr(u32 *pir, void *regs);
void kvm_apic_update_irr(struct kvm_vcpu *vcpu, u32 *pir);
int kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq,
		     struct dest_map *dest_map);
int kvm_apic_local_deliver(struct kvm_lapic *apic, int lvt_type);

bool kvm_irq_delivery_to_apic_fast(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq, int *r, struct dest_map *dest_map);

u64 kvm_get_apic_base(struct kvm_vcpu *vcpu);
int kvm_set_apic_base(struct kvm_vcpu *vcpu, struct msr_data *msr_info);
int kvm_apic_get_state(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s);
int kvm_apic_set_state(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s);
int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu);

void kvm_apic_write_nodecode(struct kvm_vcpu *vcpu, u32 offset);
void kvm_apic_set_eoi_accelerated(struct kvm_vcpu *vcpu, int vector);

int kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr);
void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu);
void kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu);

int kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, u32 msr, u64 data);
int kvm_x2apic_msr_read(struct kvm_vcpu *vcpu, u32 msr, u64 *data);

void kvm_lapic_init(void);

#define VEC_POS(v) ((v) & (32 - 1))
#define REG_POS(v) (((v) >> 5) << 4)

static inline void kvm_lapic_set_vector(int vec, void *bitmap)
{
	set_bit(VEC_POS(vec), (size_t *)((u8 *)(bitmap) + REG_POS(vec)));
}

static inline void kvm_lapic_set_irr(int vec, struct kvm_lapic *apic)
{
	kvm_lapic_set_vector(vec, (unsigned char *)apic->regs + APIC_IRR);
	/*
	 * irr_pending must be true if any interrupt is pending; set it after
	 * APIC_IRR to avoid race with apic_clear_irr
	 */
	apic->irr_pending = true;
}

static inline u32 kvm_lapic_get_reg(struct kvm_lapic *apic, int reg_off)
{
	return *((u32 *) ((unsigned char *)apic->regs + reg_off));
}

static inline void kvm_lapic_set_reg(struct kvm_lapic *apic, int reg_off, u32 val)
{
	*((u32 *) ((unsigned char *)apic->regs + reg_off)) = val;
}

static inline bool lapic_in_kernel(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic;
}

static inline int kvm_apic_hw_enabled(struct kvm_lapic *apic)
{
	return apic->vcpu->arch.apic_base & MSR_IA32_APICBASE_ENABLE;
}

static inline bool kvm_apic_sw_enabled(struct kvm_lapic *apic)
{
	return apic->sw_enabled;
}

static inline bool kvm_apic_present(struct kvm_vcpu *vcpu)
{
	return lapic_in_kernel(vcpu) && kvm_apic_hw_enabled(vcpu->arch.apic);
}

static inline int kvm_lapic_enabled(struct kvm_vcpu *vcpu)
{
	return kvm_apic_present(vcpu) && kvm_apic_sw_enabled(vcpu->arch.apic);
}

static inline int apic_x2apic_mode(struct kvm_lapic *apic)
{
	return apic->vcpu->arch.apic_base & X2APIC_ENABLE;
}

static inline bool kvm_vcpu_apicv_active(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic && vcpu->arch.apicv_active;
}

static inline bool kvm_apic_has_events(struct kvm_vcpu *vcpu)
{
	return lapic_in_kernel(vcpu) && vcpu->arch.apic->pending_events;
}

static inline bool kvm_lowest_prio_delivery(struct kvm_lapic_irq *irq)
{
	return (irq->delivery_mode == APIC_DM_LOWEST ||
			irq->msi_redir_hint);
}

static inline int kvm_lapic_latched_init(struct kvm_vcpu *vcpu)
{
	return lapic_in_kernel(vcpu) && test_bit(AEHD_APIC_INIT, &vcpu->arch.apic->pending_events);
}

static inline u32 kvm_apic_id(struct kvm_lapic *apic)
{
	/* To avoid a race between apic_base and following APIC_ID update when
	 * switching to x2apic_mode, the x2apic mode returns initial x2apic id.
	 */
	if (apic_x2apic_mode(apic))
		return apic->vcpu->vcpu_id;

	return kvm_lapic_get_reg(apic, APIC_ID) >> 24;
}

bool kvm_apic_pending_eoi(struct kvm_vcpu *vcpu, int vector);

bool kvm_intr_is_single_vcpu_fast(struct kvm *kvm, struct kvm_lapic_irq *irq,
			struct kvm_vcpu **dest_vcpu);
int kvm_vector_to_index(u32 vector, u32 dest_vcpus,
			const size_t *bitmap, u32 bitmap_size);
#endif
