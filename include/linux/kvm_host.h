/*
 * Copyright 2019 Google LLC
 */

#ifndef __KVM_HOST_H
#define __KVM_HOST_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <uapi/linux/kvm.h>

#include <linux/kvm_types.h>

#include <asm/kvm_host.h>

#include <gvm-main.h>
#include <ntkrutils.h>

#ifndef GVM_MAX_VCPU_ID
#define GVM_MAX_VCPU_ID GVM_MAX_VCPUS
#endif

/*
 * The bit 16 ~ bit 31 of kvm_memory_region::flags are internally used
 * in kvm, other bits are visible for userspace which are defined in
 * include/linux/kvm_h.
 */
#define GVM_MEMSLOT_INVALID	(1ULL << 16)
#define GVM_MEMSLOT_INCOHERENT	(1ULL << 17)

/* Two fragments for cross MMIO pages. */
#define GVM_MAX_MMIO_FRAGMENTS	2

#ifndef GVM_ADDRESS_SPACE_NUM
#define GVM_ADDRESS_SPACE_NUM	1
#endif

/*
 * For the normal pfn, the highest 12 bits should be zero,
 * so we can mask bit 62 ~ bit 52  to indicate the error pfn,
 * mask bit 63 to indicate the noslot pfn.
 */
#define GVM_PFN_ERR_MASK	(0x7ffULL << 52)
#define GVM_PFN_ERR_NOSLOT_MASK	(0xfffULL << 52)
#define GVM_PFN_NOSLOT		(0x1ULL << 63)

#define GVM_PFN_ERR_FAULT	(GVM_PFN_ERR_MASK)
#define GVM_PFN_ERR_HWPOISON	(GVM_PFN_ERR_MASK + 1)
#define GVM_PFN_ERR_RO_FAULT	(GVM_PFN_ERR_MASK + 2)

/*
 * error pfns indicate that the gfn is in slot but faild to
 * translate it to pfn on host.
 */
static inline bool is_error_pfn(kvm_pfn_t pfn)
{
	return !!(pfn & GVM_PFN_ERR_MASK);
}

/*
 * error_noslot pfns indicate that the gfn can not be
 * translated to pfn - it is not in slot or failed to
 * translate it to pfn.
 */
static inline bool is_error_noslot_pfn(kvm_pfn_t pfn)
{
	return !!(pfn & GVM_PFN_ERR_NOSLOT_MASK);
}

/* noslot pfn indicates that the gfn is not in slot. */
static inline bool is_noslot_pfn(kvm_pfn_t pfn)
{
	return pfn == GVM_PFN_NOSLOT;
}

/*
 * According to Windows Virtual Space, it is the middle of [0, 2^64-1]
 * that is least likely to be used. We grab two to server as our
 * bad hva.
 */
#define GVM_HVA_ERR_BAD		(0x8000000000000000)
#define GVM_HVA_ERR_RO_BAD	(GVM_HVA_ERR_BAD + PAGE_SIZE)

static inline bool kvm_is_error_hva(size_t addr)
{
	return addr == GVM_HVA_ERR_BAD || addr == GVM_HVA_ERR_RO_BAD;
}

#define GVM_ERR_PTR_BAD_PAGE	(ERR_PTR(-ENOENT))

static inline bool is_error_page(struct page *page)
{
	return IS_ERR(page);
}

/*
 * Architecture-independent vcpu->requests bit members
 * Bits 4-7 are reserved for more arch-independent bits.
 */
#define GVM_REQ_TLB_FLUSH          0
#define GVM_REQ_MMU_RELOAD         1
#define GVM_REQ_PENDING_TIMER      2
#define GVM_REQ_UNHALT             3

#define GVM_USERSPACE_IRQ_SOURCE_ID		0

extern struct kmem_cache *kvm_vcpu_cache;

extern spinlock_t kvm_lock;
extern struct list_head vm_list;

struct kvm_io_range {
	gpa_t addr;
	int len;
	struct kvm_io_device *dev;
};

#define NR_IOBUS_DEVS 1000

struct kvm_io_bus {
	int dev_count;
	struct kvm_io_range range[];
};

enum kvm_bus {
	GVM_MMIO_BUS,
	GVM_PIO_BUS,
	GVM_VIRTIO_CCW_NOTIFY_BUS,
	GVM_FAST_MMIO_BUS,
	GVM_NR_BUSES
};

int kvm_io_bus_write(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val);
int kvm_io_bus_write_cookie(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx,
			    gpa_t addr, int len, const void *val, long cookie);
int kvm_io_bus_read(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		    int len, void *val);
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
			    int len, struct kvm_io_device *dev);
int kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			      struct kvm_io_device *dev);
struct kvm_io_device *kvm_io_bus_get_dev(struct kvm *kvm, enum kvm_bus bus_idx,
					 gpa_t addr);

enum {
	OUTSIDE_GUEST_MODE,
	IN_GUEST_MODE,
	EXITING_GUEST_MODE,
	READING_SHADOW_PAGE_TABLES,
};

/*
 * Sometimes a large or cross-page mmio needs to be broken up into separate
 * exits for userspace servicing.
 */
struct kvm_mmio_fragment {
	gpa_t gpa;
	void *data;
	unsigned len;
};

struct kvm_vcpu {
	struct kvm *kvm;
	int cpu;
	int vcpu_id;
	int srcu_idx;
	int mode;
	size_t requests;
	size_t guest_debug;

	int pre_pcpu;
	struct list_head blocked_vcpu_list;

	struct mutex mutex;
	struct kvm_run *run;
	size_t run_userva;

	int guest_xcr0_loaded;
	KEVENT kick_event;
	u64 blocked;
	PETHREAD thread;
	KAPC apc;
	KTIMER run_timer;
	KDPC run_timer_dpc;
	struct kvm_vcpu_stat stat;
	bool valid_wakeup;

	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_cur_fragment;
	int mmio_nr_fragments;
	struct kvm_mmio_fragment mmio_fragments[GVM_MAX_MMIO_FRAGMENTS];

	bool preempted;
	struct kvm_vcpu_arch arch;
};

static inline int kvm_vcpu_exiting_guest_mode(struct kvm_vcpu *vcpu)
{
	return cmpxchg(&vcpu->mode, IN_GUEST_MODE, EXITING_GUEST_MODE);
}

/*
 * Some of the bitops functions do not support too long bitmaps.
 * This number must be determined not to exceed such limits.
 */
#define GVM_MEM_MAX_NR_PAGES ((1ULL << 31) - 1)

struct pmem_lock {
	/* Lock to prevent multiple fault in to the same pfn
	 * but allow to different pfns.
	 */
	spinlock_t lock;
	PMDL lock_mdl;
};

struct kvm_memory_slot {
	gfn_t base_gfn;
	size_t npages;
	size_t *dirty_bitmap;
	struct kvm_arch_memory_slot arch;
	size_t userspace_addr;
	u32 flags;
	short id;
	struct pmem_lock *pmem_lock;
};

#define ALIGN(x, mask)    (((x) + (mask - 1)) & ~(mask - 1))
#define IS_ALIGNED(x, a)    (((x) & ((u64)(a) - 1)) == 0)
#define PAGE_ALIGNED(addr) IS_ALIGNED((size_t)(addr), PAGE_SIZE)

static inline size_t kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	return ALIGN(memslot->npages, (size_t)BITS_PER_LONG) / 8;
}

struct kvm_kernel_irq_routing_entry {
	u32 gsi;
	u32 type;
	int (*set)(struct kvm_kernel_irq_routing_entry *e,
		   struct kvm *kvm, int irq_source_id, int level,
		   bool line_status);
	union {
		struct {
			unsigned irqchip;
			unsigned pin;
		} irqchip;
		struct {
			u32 address_lo;
			u32 address_hi;
			u32 data;
			u32 flags;
			u32 devid;
		} msi;
	};
	struct hlist_node link;
};

struct kvm_irq_routing_table {
	int chip[GVM_NR_IRQCHIPS][GVM_IRQCHIP_NUM_PINS];
	u32 nr_rt_entries;
	/*
	 * Array indexed by gsi. Each entry contains list of irq chips
	 * the gsi is connected to.
	 */
	struct hlist_head map[0];
};

#ifndef GVM_PRIVATE_MEM_SLOTS
#define GVM_PRIVATE_MEM_SLOTS 0
#endif

#ifndef GVM_MEM_SLOTS_NUM
#define GVM_MEM_SLOTS_NUM (GVM_USER_MEM_SLOTS + GVM_PRIVATE_MEM_SLOTS)
#endif

#ifndef __GVM_VCPU_MULTIPLE_ADDRESS_SPACE
static inline int kvm_arch_vcpu_memslots_id(struct kvm_vcpu *vcpu)
{
	return 0;
}
#endif

/*
 * Note:
 * memslots are not sorted by id anymore, please use id_to_memslot()
 * to get the memslot by its id.
 */
struct kvm_memslots {
	u64 generation;
	struct kvm_memory_slot memslots[GVM_MEM_SLOTS_NUM];
	/* The mapping table from slot id to the index in memslots[]. */
	short id_to_index[GVM_MEM_SLOTS_NUM];
	atomic_t lru_slot;
	int used_slots;
};

struct kvm {
	spinlock_t mmu_lock;
	struct mutex slots_lock;
	PEPROCESS process;
	u64 vm_id;
	struct kvm_memslots *memslots[GVM_ADDRESS_SPACE_NUM];
	struct kvm_vcpu *vcpus[GVM_MAX_VCPUS];

	/*
	 * created_vcpus is protected by kvm->lock, and is incremented
	 * at the beginning of GVM_CREATE_VCPU.  online_vcpus is only
	 * incremented after storing the kvm_vcpu pointer in vcpus,
	 * and is accessed atomically.
	 */
	atomic_t online_vcpus;
	int created_vcpus;
	int last_boosted_vcpu;
	struct list_head vm_list;
	struct mutex lock;
	struct kvm_io_bus *buses[GVM_NR_BUSES];
	struct kvm_vm_stat stat;
	struct kvm_arch arch;
	atomic_t users_count;

	struct mutex irq_lock;
	/*
	 * Update side is protected by irq_lock.
	 */
	struct kvm_irq_routing_table *irq_routing;

	long tlbs_dirty;
	struct srcu_struct srcu;
	struct srcu_struct irq_srcu;
};

#define kvm_err(fmt, ...) \
	pr_err("kvm: " fmt, ## __VA_ARGS__)
#define kvm_info(fmt, ...) \
	pr_info("kvm: " fmt, ## __VA_ARGS__)
#define kvm_debug(fmt, ...) \
	pr_debug("kvm: " fmt, ## __VA_ARGS__)
#define kvm_pr_unimpl(fmt, ...) \
	pr_err_ratelimited("kvm: " fmt, \
			   ## __VA_ARGS__)

/* The guest did something we don't support. */
#define vcpu_unimpl(vcpu, fmt, ...)					\
	kvm_pr_unimpl("vcpu%i, guest rIP: 0x%lx " fmt,			\
			(vcpu)->vcpu_id, kvm_rip_read(vcpu), ## __VA_ARGS__)

#define vcpu_debug(vcpu, fmt, ...)					\
	kvm_debug("vcpu%i " fmt, (vcpu)->vcpu_id, ## __VA_ARGS__)
#define vcpu_err(vcpu, fmt, ...)					\
	kvm_err("vcpu%i " fmt, (vcpu)->vcpu_id, ## __VA_ARGS__)

static inline struct kvm_vcpu *kvm_get_vcpu(struct kvm *kvm, int i)
{
	/* Pairs with smp_wmb() in kvm_vm_ioctl_create_vcpu, in case
	 * the caller has read kvm->online_vcpus before (as is the case
	 * for kvm_for_each_vcpu, for example).
	 */
	smp_rmb();
	return kvm->vcpus[i];
}

#define kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0; \
	     idx < atomic_read(&kvm->online_vcpus) && \
	     (vcpup = kvm_get_vcpu(kvm, idx)) != NULL; \
	     idx++)

static inline struct kvm_vcpu *kvm_get_vcpu_by_id(struct kvm *kvm, int id)
{
	struct kvm_vcpu *vcpu = NULL;
	int i;

	if (id < 0)
		return NULL;
	if (id < GVM_MAX_VCPUS)
		vcpu = kvm_get_vcpu(kvm, id);
	if (vcpu && vcpu->vcpu_id == id)
		return vcpu;
	kvm_for_each_vcpu(i, vcpu, kvm)
		if (vcpu->vcpu_id == id)
			return vcpu;
	return NULL;
}

#define kvm_for_each_memslot(memslot, slots)	\
	for (memslot = &slots->memslots[0];	\
	      memslot < slots->memslots + GVM_MEM_SLOTS_NUM && memslot->npages;\
		memslot++)

int kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id);
void kvm_vcpu_uninit(struct kvm_vcpu *vcpu);

int __must_check vcpu_load(struct kvm_vcpu *vcpu);
void vcpu_put(struct kvm_vcpu *vcpu);

void kvm_vcpu_request_scan_ioapic(struct kvm *kvm);
void kvm_arch_post_irq_routing_update(struct kvm *kvm);

int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align);
void kvm_exit(void);

void kvm_get_kvm(struct kvm *kvm);
void kvm_put_kvm(struct kvm *kvm);

static inline struct kvm_memslots *__kvm_memslots(struct kvm *kvm, int as_id)
{
	return kvm->memslots[as_id];
#if 0
	return rcu_dereference_check(kvm->memslots[as_id],
			srcu_read_lock_held(&kvm->srcu)
			|| lockdep_is_held(&kvm->slots_lock));
#endif
}

static inline struct kvm_memslots *kvm_memslots(struct kvm *kvm)
{
	return __kvm_memslots(kvm, 0);
}

static inline struct kvm_memslots *kvm_vcpu_memslots(struct kvm_vcpu *vcpu)
{
	int as_id = kvm_arch_vcpu_memslots_id(vcpu);

	return __kvm_memslots(vcpu->kvm, as_id);
}

static inline struct kvm_memory_slot *
id_to_memslot(struct kvm_memslots *slots, int id)
{
	int index = slots->id_to_index[id];
	struct kvm_memory_slot *slot;

	slot = &slots->memslots[index];

	WARN_ON(slot->id != id);
	return slot;
}

/*
 * GVM_SET_USER_MEMORY_REGION ioctl allows the following operations:
 * - create a new memory slot
 * - delete an existing memory slot
 * - modify an existing memory slot
 *   -- move it in the guest physical memory space
 *   -- just change its flags
 *
 * Since flags can be changed by some of these operations, the following
 * differentiation is the best we can do for __kvm_set_memory_region():
 */
enum kvm_mr_change {
	GVM_MR_CREATE,
	GVM_MR_DELETE,
	GVM_MR_MOVE,
	GVM_MR_FLAGS_ONLY,
};

int kvm_set_memory_region(struct kvm *kvm,
			  const struct kvm_userspace_memory_region *mem);
int __kvm_set_memory_region(struct kvm *kvm,
			    const struct kvm_userspace_memory_region *mem);
void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			   struct kvm_memory_slot *dont);
int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
			    size_t npages);
void kvm_arch_memslots_updated(struct kvm *kvm, struct kvm_memslots *slots);
int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				const struct kvm_userspace_memory_region *mem,
				enum kvm_mr_change change);
void kvm_arch_commit_memory_region(struct kvm *kvm,
				const struct kvm_userspace_memory_region *mem,
				const struct kvm_memory_slot *old,
				const struct kvm_memory_slot *new,
				enum kvm_mr_change change);
/* flush all memory translations */
void kvm_arch_flush_shadow_all(struct kvm *kvm);
/* flush memory translations pointing to 'slot' */
void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot);

int gfn_to_pfn_many_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			   pfn_t *pfn, int nr_pages);

size_t gfn_to_hva(struct kvm *kvm, gfn_t gfn);
size_t gfn_to_hva_prot(struct kvm *kvm, gfn_t gfn, bool *writable);
size_t gfn_to_hva_memslot(struct kvm_memory_slot *slot, gfn_t gfn);
size_t gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot, gfn_t gfn,
				      bool *writable);
kvm_pfn_t gfn_to_pfn_atomic(struct kvm *kvm, gfn_t gfn);
kvm_pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn);
kvm_pfn_t gfn_to_pfn_prot(struct kvm *kvm, gfn_t gfn, bool write_fault,
		      bool *writable);
kvm_pfn_t gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn);
kvm_pfn_t gfn_to_pfn_memslot_atomic(struct kvm_memory_slot *slot, gfn_t gfn);
kvm_pfn_t __gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable);

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len);
int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, size_t len);
int kvm_read_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, size_t len);
int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn, const void *data,
			 int offset, int len);
int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    size_t len);
int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, size_t len);
int kvm_gfn_to_hva_cache_init(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			      gpa_t gpa, size_t len);
int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len);
int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, size_t len);
struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn);
bool kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn);
size_t kvm_host_page_size(struct kvm *kvm, gfn_t gfn);
void mark_page_dirty(struct kvm *kvm, gfn_t gfn);

struct kvm_memslots *kvm_vcpu_memslots(struct kvm_vcpu *vcpu);
struct kvm_memory_slot *kvm_vcpu_gfn_to_memslot(struct kvm_vcpu *vcpu, gfn_t gfn);
kvm_pfn_t kvm_vcpu_gfn_to_pfn_atomic(struct kvm_vcpu *vcpu, gfn_t gfn);
kvm_pfn_t kvm_vcpu_gfn_to_pfn(struct kvm_vcpu *vcpu, gfn_t gfn);
struct page *kvm_vcpu_gfn_to_page(struct kvm_vcpu *vcpu, gfn_t gfn);
size_t kvm_vcpu_gfn_to_hva(struct kvm_vcpu *vcpu, gfn_t gfn);
size_t kvm_vcpu_gfn_to_hva_prot(struct kvm_vcpu *vcpu, gfn_t gfn, bool *writable);
int kvm_vcpu_read_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn, void *data, int offset,
			     int len);
int kvm_vcpu_read_guest_atomic(struct kvm_vcpu *vcpu, gpa_t gpa, void *data,
			       size_t len);
int kvm_vcpu_read_guest(struct kvm_vcpu *vcpu, gpa_t gpa, void *data,
			size_t len);
int kvm_vcpu_write_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn, const void *data,
			      int offset, int len);
int kvm_vcpu_write_guest(struct kvm_vcpu *vcpu, gpa_t gpa, const void *data,
			 size_t len);
void kvm_vcpu_mark_page_dirty(struct kvm_vcpu *vcpu, gfn_t gfn);

void kvm_vcpu_block(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu);
void kvm_vcpu_wake_up(struct kvm_vcpu *vcpu);
void kvm_vcpu_kick(struct kvm_vcpu *vcpu);
int kvm_vcpu_yield_to(struct kvm_vcpu *target);
void kvm_vcpu_on_spin(struct kvm_vcpu *vcpu);
void kvm_load_guest_fpu(struct kvm_vcpu *vcpu);
void kvm_save_guest_fpu(struct kvm_vcpu *vcpu);

void kvm_flush_remote_tlbs(struct kvm *kvm);
void kvm_reload_remote_mmus(struct kvm *kvm);
bool kvm_make_all_cpus_request(struct kvm *kvm, unsigned int req);

long kvm_arch_dev_ioctl(struct gvm_device_extension *devext, PIRP pIrp,
			unsigned int ioctl);
long kvm_arch_vcpu_ioctl(struct gvm_device_extension *devext, PIRP pIrp,
			 unsigned int ioctl);

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext);

int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty);

int kvm_get_dirty_log_protect(struct kvm *kvm,
			struct kvm_dirty_log *log, bool *is_dirty);

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
					struct kvm_memory_slot *slot,
					gfn_t gfn_offset,
					size_t mask);

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log);

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
			bool line_status);
long kvm_arch_vm_ioctl(struct gvm_device_extension *devext, PIRP pIrp,
		       unsigned int ioctl);

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu);
int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu);

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				    struct kvm_translation *tr);

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);
int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);
int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs);
int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs);
int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state);
int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state);
int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg);
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);

int kvm_arch_init(void *opaque);
void kvm_arch_exit(void);

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu);

void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu);

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu);
struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id);
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu);

int kvm_arch_hardware_enable(void);
void kvm_arch_hardware_disable(void);
int kvm_arch_hardware_setup(void);
void kvm_arch_hardware_unsetup(void);
void kvm_arch_check_processor_compat(void *rtn);
int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu);
int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu);

void *kvm_kvzalloc(size_t size);

#ifndef __GVM_HAVE_ARCH_VM_ALLOC
static inline struct kvm *kvm_arch_alloc_vm(void)
{
	return kzalloc(sizeof(struct kvm), GFP_KERNEL);
}

static inline void kvm_arch_free_vm(struct kvm *kvm)
{
	kfree(kvm);
}
#endif

#ifdef __GVM_HAVE_ARCH_INTC_INITIALIZED
/*
 * returns true if the virtual interrupt controller is initialized and
 * ready to accept virtual IRQ. On some architectures the virtual interrupt
 * controller is dynamically instantiated and this is not always true.
 */
bool kvm_arch_intc_initialized(struct kvm *kvm);
#else
static inline bool kvm_arch_intc_initialized(struct kvm *kvm)
{
	return true;
}
#endif

int kvm_arch_init_vm(struct kvm *kvm, size_t type);
void kvm_arch_destroy_vm(struct kvm *kvm);

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_vcpu_kick(struct kvm_vcpu *vcpu);

int kvm_irq_map_gsi(struct kvm *kvm,
		    struct kvm_kernel_irq_routing_entry *entries, int gsi);
int kvm_irq_map_chip_pin(struct kvm *kvm, unsigned irqchip, unsigned pin);

int kvm_set_irq(struct kvm *kvm, int irq_source_id, u32 irq, int level,
		bool line_status);
int kvm_set_msi(struct kvm_kernel_irq_routing_entry *irq_entry, struct kvm *kvm,
		int irq_source_id, int level, bool line_status);
int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
			       struct kvm *kvm, int irq_source_id,
			       int level, bool line_status);
bool kvm_irq_has_notifier(struct kvm *kvm, unsigned irqchip, unsigned pin);
void kvm_notify_acked_gsi(struct kvm *kvm, int gsi);
void kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin);
int kvm_request_irq_source_id(struct kvm *kvm);
void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id);

/*
 * search_memslots() and __gfn_to_memslot() are here because they are
 * used in non-modular code in arch/powerpc/kvm/book3s_hv_rm_mmu.c.
 * gfn_to_memslot() itself isn't here as an inline because that would
 * bloat other code too much.
 */
static inline struct kvm_memory_slot *
search_memslots(struct kvm_memslots *slots, gfn_t gfn)
{
	int start = 0, end = slots->used_slots;
	int slot = atomic_read(&slots->lru_slot);
	struct kvm_memory_slot *memslots = slots->memslots;

	if (gfn >= memslots[slot].base_gfn &&
	    gfn < memslots[slot].base_gfn + memslots[slot].npages)
		return &memslots[slot];

	while (start < end) {
		slot = start + (end - start) / 2;

		if (gfn >= memslots[slot].base_gfn)
			end = slot;
		else
			start = slot + 1;
	}

	if (gfn >= memslots[start].base_gfn &&
	    gfn < memslots[start].base_gfn + memslots[start].npages) {
		atomic_set(&slots->lru_slot, start);
		return &memslots[start];
	}

	return NULL;
}

static inline struct kvm_memory_slot *
__gfn_to_memslot(struct kvm_memslots *slots, gfn_t gfn)
{
	return search_memslots(slots, gfn);
}

static inline size_t
__gfn_to_hva_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return slot->userspace_addr + (gfn - slot->base_gfn) * PAGE_SIZE;
}

static inline int memslot_id(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_memslot(kvm, gfn)->id;
}

static inline gfn_t
hva_to_gfn_memslot(size_t hva, struct kvm_memory_slot *slot)
{
	gfn_t gfn_offset = (hva - slot->userspace_addr) >> PAGE_SHIFT;

	return slot->base_gfn + gfn_offset;
}

static inline gpa_t gfn_to_gpa(gfn_t gfn)
{
	return (gpa_t)gfn << PAGE_SHIFT;
}

static inline gfn_t gpa_to_gfn(gpa_t gpa)
{
	return (gfn_t)(gpa >> PAGE_SHIFT);
}

static inline hpa_t pfn_to_hpa(kvm_pfn_t pfn)
{
	return (hpa_t)pfn << PAGE_SHIFT;
}

static inline bool kvm_is_error_gpa(struct kvm *kvm, gpa_t gpa)
{
	size_t hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	return kvm_is_error_hva(hva);
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(GVM_ARCH_WANT_MMU_NOTIFIER)
static inline int mmu_notifier_retry(struct kvm *kvm, size_t mmu_seq)
{
	if (unlikely(kvm->mmu_notifier_count))
		return 1;
	/*
	 * Ensure the read of mmu_notifier_count happens before the read
	 * of mmu_notifier_seq.  This interacts with the smp_wmb() in
	 * mmu_notifier_invalidate_range_end to make sure that the caller
	 * either sees the old (non-zero) value of mmu_notifier_count or
	 * the new (incremented) value of mmu_notifier_seq.
	 * PowerPC Book3s HV kvm calls this under a per-page lock
	 * rather than under kvm->mmu_lock, for scalability, so
	 * can't rely on kvm->mmu_lock to keep things ordered.
	 */
	smp_rmb();
	if (kvm->mmu_notifier_seq != mmu_seq)
		return 1;
	return 0;
}
#endif


#define GVM_MAX_IRQ_ROUTES 1024

int kvm_set_irq_routing(struct kvm *kvm,
			const struct kvm_irq_routing_entry *entries,
			unsigned nr,
			unsigned flags);
int kvm_set_routing_entry(struct kvm *kvm,
			  struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue);
void kvm_free_irq_routing(struct kvm *kvm);

int kvm_send_userspace_msi(struct kvm *kvm, struct kvm_msi *msi);

static inline void kvm_make_request(int req, struct kvm_vcpu *vcpu)
{
	/*
	 * Ensure the rest of the request is published to kvm_check_request's
	 * caller.  Paired with the smp_mb__after_atomic in kvm_check_request.
	 */
	smp_wmb();
	set_bit(req, &vcpu->requests);
}

static inline bool kvm_check_request(int req, struct kvm_vcpu *vcpu)
{
	if (test_bit(req, &vcpu->requests)) {
		clear_bit(req, &vcpu->requests);

		/*
		 * Ensure the rest of the request is visible to kvm_check_request's
		 * caller.  Paired with the smp_wmb in kvm_make_request.
		 */
		smp_mb__after_atomic();
		return true;
	} else {
		return false;
	}
}

extern bool kvm_rebooting;

#ifdef CONFIG_HAVE_GVM_INVALID_WAKEUPS
/* If we wakeup during the poll time, was it a sucessful poll? */
static inline bool vcpu_valid_wakeup(struct kvm_vcpu *vcpu)
{
	return vcpu->valid_wakeup;
}

#else
static inline bool vcpu_valid_wakeup(struct kvm_vcpu *vcpu)
{
	return true;
}
#endif /* CONFIG_HAVE_GVM_INVALID_WAKEUPS */

#endif
