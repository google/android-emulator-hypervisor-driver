/*
 * Copyright 2019 Google LLC
 */

#ifndef __KVM_IO_APIC_H
#define __KVM_IO_APIC_H

#include <linux/kvm_host.h>

#include <kvm/iodev.h>

#include <aehd_types.h>

struct kvm;
struct kvm_vcpu;

#define IOAPIC_NUM_PINS  AEHD_IOAPIC_NUM_PINS
#define MAX_NR_RESERVED_IOAPIC_PINS AEHD_MAX_IRQ_ROUTES
#define IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define IOAPIC_EDGE_TRIG  0
#define IOAPIC_LEVEL_TRIG 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define IOAPIC_REG_SELECT  0x00
#define IOAPIC_REG_WINDOW  0x10

/* Indirect registers. */
#define IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define IOAPIC_REG_VERSION 0x01
#define IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/*ioapic delivery mode*/
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

#define RTC_GSI 8

struct dest_map {
	/* vcpu bitmap where IRQ has been sent */
	DECLARE_BITMAP(map, AEHD_MAX_VCPU_ID);

	/*
	 * Vector sent to a given vcpu, only valid when
	 * the vcpu's bit in map is set
	 */
	u8 vectors[AEHD_MAX_VCPU_ID];
};


struct rtc_status {
	int pending_eoi;
	struct dest_map dest_map;
};

union kvm_ioapic_redirect_entry {
	u64 bits;
	struct {
		u8 vector;
		u8 delivery_mode:3;
		u8 dest_mode:1;
		u8 delivery_status:1;
		u8 polarity:1;
		u8 remote_irr:1;
		u8 trig_mode:1;
		u8 mask:1;
		u8 reserve:7;
		u8 reserved[4];
		u8 dest_id;
	} fields;
};

struct kvm_ioapic {
	u64 base_address;
	u32 ioregsel;
	u32 id;
	u32 irr;
	u32 pad;
	union kvm_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];
	size_t irq_states[IOAPIC_NUM_PINS];
	struct kvm_io_device dev;
	struct kvm *kvm;
	void (*ack_notifier)(void *opaque, int irq);
	spinlock_t lock;
	struct rtc_status rtc_status;
	u32 irq_eoi[IOAPIC_NUM_PINS];
	u32 irr_delivered;
};

static inline struct kvm_ioapic *ioapic_irqchip(struct kvm *kvm)
{
	return kvm->arch.vioapic;
}

static inline int ioapic_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ioapic_irqchip(kvm) != NULL);
	return ret;
}

void kvm_rtc_eoi_tracking_restore_one(struct kvm_vcpu *vcpu);
bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
		int short_hand, unsigned int dest, int dest_mode);
int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);
void kvm_ioapic_update_eoi(struct kvm_vcpu *vcpu, int vector,
			int trigger_mode);
int kvm_ioapic_init(struct kvm *kvm);
void kvm_ioapic_destroy(struct kvm *kvm);
int kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int irq_source_id,
		       int level, bool line_status);
void kvm_ioapic_clear_all(struct kvm_ioapic *ioapic, int irq_source_id);
int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
			     struct kvm_lapic_irq *irq,
			     struct dest_map *dest_map);
int kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
int kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_ioapic_scan_entry(struct kvm_vcpu *vcpu,
			   ulong *ioapic_handled_vectors);
void kvm_scan_ioapic_routes(struct kvm_vcpu *vcpu,
			    ulong *ioapic_handled_vectors);
#endif
