/*
 * Copyright 2019 Google LLC
 *
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines architecture specific interfaces, x86 version
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _ASM_X86_KVM_HOST_H
#define _ASM_X86_KVM_HOST_H

#include <linux/kvm_types.h>
#include <asm/kvm_page_track.h>

#include <asm/fpu/types.h>
#include <uapi/asm/kvm.h>
#include <ntkrutils.h>
#include <__asm.h>

#define GVM_MAX_VCPUS 288
#define GVM_SOFT_MAX_VCPUS 240
#define GVM_MAX_VCPU_ID 1023
#define GVM_USER_MEM_SLOTS 125
/* memory slots that are not exposed to userspace */
#define GVM_PRIVATE_MEM_SLOTS 3
#define GVM_MEM_SLOTS_NUM (GVM_USER_MEM_SLOTS + GVM_PRIVATE_MEM_SLOTS)

#define GVM_PIO_PAGE_OFFSET 1

#define GVM_IRQCHIP_NUM_PINS  GVM_IOAPIC_NUM_PINS

/* x86-specific vcpu->requests bit members */
#define GVM_REQ_REPORT_TPR_ACCESS  9
#define GVM_REQ_TRIPLE_FAULT      10
#define GVM_REQ_MMU_SYNC          11
#define GVM_REQ_EVENT             14
#define GVM_REQ_NMI               17
#define GVM_REQ_PMU               18
#define GVM_REQ_PMI               19
#define GVM_REQ_SMI               20
#define GVM_REQ_SCAN_IOAPIC       23
#define GVM_REQ_GLOBAL_CLOCK_UPDATE 24
#define GVM_REQ_APIC_PAGE_RELOAD  25

#define CR0_RESERVED_BITS                                               \
	(~(size_t)(X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS \
			  | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM \
			  | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG))

#define CR3_L_MODE_RESERVED_BITS 0xFFFFFF0000000000ULL
#define BIT_64(a) (unsigned long long)(a)
#define CR3_PCID_INVD		 BIT_64(63)
#define CR4_RESERVED_BITS                                               \
	(~(size_t)(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE\
			  | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE     \
			  | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR | X86_CR4_PCIDE \
			  | X86_CR4_OSXSAVE | X86_CR4_SMEP | X86_CR4_FSGSBASE \
			  | X86_CR4_OSXMMEXCPT | X86_CR4_VMXE | X86_CR4_SMAP \
			  | X86_CR4_PKE))

#define CR8_RESERVED_BITS (~(size_t)X86_CR8_TPR)



/* Let we assume Windows won't give us a page at BIOS range */
#define INVALID_PAGE (~(hpa_t)0xFFFF)
#define VALID_PAGE(x) ((x) != INVALID_PAGE)

#define UNMAPPED_GVA (~(gpa_t)0)

#define GVM_PERMILLE_MMU_PAGES 20
#define GVM_MIN_ALLOC_MMU_PAGES 64
#define GVM_MMU_HASH_SHIFT 10
#define GVM_NUM_MMU_PAGES (1 << GVM_MMU_HASH_SHIFT)
#define GVM_MIN_FREE_MMU_PAGES 5
#define GVM_REFILL_PAGES 25
#define GVM_MAX_CPUID_ENTRIES 80
#define GVM_NR_FIXED_MTRR_REGION 88
#define GVM_NR_VAR_MTRR 8

enum kvm_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

enum kvm_reg_ex {
	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
	VCPU_EXREG_CR3,
	VCPU_EXREG_RFLAGS,
	VCPU_EXREG_SEGMENTS,
};

enum {
	VCPU_SREG_ES,
	VCPU_SREG_CS,
	VCPU_SREG_SS,
	VCPU_SREG_DS,
	VCPU_SREG_FS,
	VCPU_SREG_GS,
	VCPU_SREG_TR,
	VCPU_SREG_LDTR,
};

#include <asm/kvm_emulate.h>

#define GVM_NR_MEM_OBJS 40

#define GVM_NR_DB_REGS	4

#define DR6_BD		(1 << 13)
#define DR6_BS		(1 << 14)
#define DR6_RTM		(1 << 16)
#define DR6_FIXED_1	0xfffe0ff0
#define DR6_INIT	0xffff0ff0
#define DR6_VOLATILE	0x0001e00f

#define DR7_BP_EN_MASK	0x000000ff
#define DR7_GE		(1 << 9)
#define DR7_GD		(1 << 13)
#define DR7_FIXED_1	0x00000400
#define DR7_VOLATILE	0xffff2bff

#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4
#define PFERR_PK_BIT 5

#define PFERR_PRESENT_MASK (1U << PFERR_PRESENT_BIT)
#define PFERR_WRITE_MASK (1U << PFERR_WRITE_BIT)
#define PFERR_USER_MASK (1U << PFERR_USER_BIT)
#define PFERR_RSVD_MASK (1U << PFERR_RSVD_BIT)
#define PFERR_FETCH_MASK (1U << PFERR_FETCH_BIT)
#define PFERR_PK_MASK (1U << PFERR_PK_BIT)

/* apic attention bits */
#define GVM_APIC_CHECK_VAPIC	0

struct kvm_kernel_irq_routing_entry;

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
struct kvm_mmu_memory_cache {
	int nobjs;
	void *objects[GVM_NR_MEM_OBJS];
};

/*
 * the pages used as guest page table on soft mmu are tracked by
 * kvm_memory_slot.arch.gfn_track which is 16 bits, so the role bits used
 * by indirect shadow page can not be more than 15 bits.
 *
 * Currently, we used 14 bits that are @level, @cr4_pae, @quadrant, @access,
 * @nxe, @cr0_wp, @smep_andnot_wp and @smap_andnot_wp.
 */
union kvm_mmu_page_role {
	unsigned word;
	struct {
		unsigned level:4;
		unsigned cr4_pae:1;
		unsigned quadrant:2;
		unsigned direct:1;
		unsigned access:3;
		unsigned invalid:1;
		unsigned nxe:1;
		unsigned cr0_wp:1;
		unsigned smep_andnot_wp:1;
		unsigned smap_andnot_wp:1;
		unsigned :8;

		/*
		 * This is left at the top of the word so that
		 * kvm_memslots_for_spte_role can extract it with a
		 * simple shift.  While there is room, give it a whole
		 * byte so it is also faster to load it from memory.
		 */
		unsigned smm:8;
	};
};

struct kvm_rmap_head {
	size_t val;
};

struct kvm_mmu_page {
	struct list_head link;
	struct hlist_node hash_link;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	gfn_t gfn;
	union kvm_mmu_page_role role;

	u64 *spt;
	/* hold the gfn of each spte inside spt */
	gfn_t *gfns;
	bool unsync;
	int root_count;          /* Currently serving as active root */
	unsigned int unsync_children;
	struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */

	/* The page is obsolete if mmu_valid_gen != kvm->arch.mmu_valid_gen.  */
	size_t mmu_valid_gen;

	DECLARE_BITMAP(unsync_child_bitmap, 512);

#ifdef CONFIG_X86_32
	/*
	 * Used out of the mmu-lock to avoid reading spte values while an
	 * update is in progress; see the comments in __get_spte_lockless().
	 */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	atomic_t write_flooding_count;
};

struct kvm_pio_request {
	size_t count;
	int in;
	int port;
	int size;
};

struct rsvd_bits_validate {
	u64 rsvd_bits_mask[2][4];
	u64 bad_mt_xwr;
};

/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit).  The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */
struct kvm_mmu {
	void (*set_cr3)(struct kvm_vcpu *vcpu, size_t root);
	size_t (*get_cr3)(struct kvm_vcpu *vcpu);
	u64 (*get_pdptr)(struct kvm_vcpu *vcpu, int index);
	int (*page_fault)(struct kvm_vcpu *vcpu, gva_t gva, u32 err);
	void (*inject_page_fault)(struct kvm_vcpu *vcpu,
				  struct x86_exception *fault);
	gpa_t (*gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
			    struct x86_exception *exception);
	gpa_t (*translate_gpa)(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
			       struct x86_exception *exception);
	int (*sync_page)(struct kvm_vcpu *vcpu,
			 struct kvm_mmu_page *sp);
	void (*invlpg)(struct kvm_vcpu *vcpu, gva_t gva);
	void (*update_pte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			   u64 *spte, const void *pte);
	hpa_t root_hpa;
	int root_level;
	int shadow_root_level;
	union kvm_mmu_page_role base_role;
	bool direct_map;

	/*
	 * Bitmap; bit set = permission fault
	 * Byte index: page fault error code [4:1]
	 * Bit index: pte permissions in ACC_* format
	 */
	u8 permissions[16];

	u64 *pae_root;
	u64 *lm_root;

	/*
	 * check zero bits on shadow page table entries, these
	 * bits include not only hardware reserved bits but also
	 * the bits spte never used.
	 */
	struct rsvd_bits_validate shadow_zero_check;

	struct rsvd_bits_validate guest_rsvd_check;

	/* Can have large pages at levels 2..last_nonleaf_level-1. */
	u8 last_nonleaf_level;

	bool nx;

	u64 pdptrs[4]; /* pae */
};

enum pmc_type {
	GVM_PMC_GP = 0,
	GVM_PMC_FIXED,
};

struct kvm_pmc {
	enum pmc_type type;
	u8 idx;
	u64 counter;
	u64 eventsel;
	struct perf_event *perf_event;
	struct kvm_vcpu *vcpu;
};

struct kvm_pmu {
	unsigned nr_arch_gp_counters;
	unsigned nr_arch_fixed_counters;
	unsigned available_event_types;
	u64 fixed_ctr_ctrl;
	u64 global_ctrl;
	u64 global_status;
	u64 global_ovf_ctrl;
	u64 counter_bitmask[2];
	u64 global_ctrl_mask;
	u64 reserved_bits;
	u8 version;
	struct kvm_pmc gp_counters[INTEL_PMC_MAX_GENERIC];
	struct kvm_pmc fixed_counters[INTEL_PMC_MAX_FIXED];
	struct irq_work irq_work;
	u64 reprogram_pmi;
};

struct kvm_pmu_ops;

enum {
	GVM_DEBUGREG_BP_ENABLED = 1,
	GVM_DEBUGREG_WONT_EXIT = 2,
	GVM_DEBUGREG_RELOAD = 4,
};

struct kvm_mtrr_range {
	u64 base;
	u64 mask;
	struct list_head node;
};

struct kvm_mtrr {
	struct kvm_mtrr_range var_ranges[GVM_NR_VAR_MTRR];
	mtrr_type fixed_ranges[GVM_NR_FIXED_MTRR_REGION];
	u64 deftype;

	struct list_head head;
};

struct kvm_vcpu_arch {
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	size_t regs[NR_VCPU_REGS];
	u32 regs_avail;
	u32 regs_dirty;

	size_t cr0;
	size_t cr0_guest_owned_bits;
	size_t cr2;
	size_t cr3;
	size_t cr4;
	size_t cr4_guest_owned_bits;
	size_t cr8;
	u32 hflags;
	u64 efer;
	u64 apic_base;
	struct kvm_lapic *apic;    /* kernel irqchip context */
	bool apicv_active;
	DECLARE_BITMAP(ioapic_handled_vectors, 256);
	size_t apic_attention;
	int32_t apic_arb_prio;
	int mp_state;
	u64 ia32_misc_enable_msr;
	u64 smbase;
	bool tpr_access_reporting;
	u64 ia32_xss;

	/*
	 * Paging state of the vcpu
	 *
	 * If the vcpu runs in guest mode with two level paging this still saves
	 * the paging mode of the l1 guest. This context is always used to
	 * handle faults.
	 */
	struct kvm_mmu mmu;

	/*
	 * Paging state of an L2 guest (used for nested npt)
	 *
	 * This context will save all necessary information to walk page tables
	 * of the an L2 guest. This context is only initialized for page table
	 * walking and not for faulting since we never handle l2 page faults on
	 * the host.
	 */
	struct kvm_mmu nested_mmu;

	/*
	 * Pointer to the mmu context currently used for
	 * gva_to_gpa translations.
	 */
	struct kvm_mmu *walk_mmu;

	struct kvm_mmu_memory_cache mmu_pte_list_desc_cache;
	struct kvm_mmu_memory_cache mmu_page_cache;
	struct kvm_mmu_memory_cache mmu_page_header_cache;

	union fpu_state host_fpu;
	union fpu_state guest_fpu;
	u64 xcr0;
	u64 guest_supported_xcr0;
	u32 guest_xstate_size;

	struct kvm_pio_request pio;
	void *pio_data;

	u8 event_exit_inst_len;

	struct kvm_queued_exception {
		bool pending;
		bool has_error_code;
		bool reinject;
		u8 nr;
		u32 error_code;
	} exception;

	struct kvm_queued_interrupt {
		bool pending;
		bool soft;
		u8 nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry cpuid_entries[GVM_MAX_CPUID_ENTRIES];

	int maxphyaddr;

	/* emulate context */

	struct x86_emulate_ctxt emulate_ctxt;
	bool emulate_regs_need_sync_to_vcpu;
	bool emulate_regs_need_sync_from_vcpu;
	int (*complete_userspace_io)(struct kvm_vcpu *vcpu);

	gpa_t time;
	unsigned int hw_tsc_khz;
	struct gfn_to_hva_cache pv_time;

	u64 tsc_offset;
	u64 last_guest_tsc;
	u64 tsc_offset_adjustment;
	s64 ia32_tsc_adjust_msr;

	atomic_t nmi_queued;  /* unprocessed asynchronous NMIs */
	unsigned nmi_pending; /* NMI queued after currently running handler */
	bool nmi_injected;    /* Trying to inject an NMI this entry */
	bool smi_pending;    /* SMI queued after currently running handler */

	struct kvm_mtrr mtrr_state;
	u64 pat;

	unsigned switch_db_regs;
	size_t db[GVM_NR_DB_REGS];
	size_t dr6;
	size_t dr7;
	size_t eff_db[GVM_NR_DB_REGS];
	size_t guest_debug_dr7;

	/* Cache MMIO info */
	u64 mmio_gva;
	unsigned access;
	gfn_t mmio_gfn;
	u64 mmio_gen;

	struct kvm_pmu pmu;

	/* used for guest single stepping over the given code position */
	size_t singlestep_rip;

	size_t last_retry_eip;
	size_t last_retry_addr;

	/* OSVW MSRs (AMD only) */
	struct {
		u64 length;
		u64 status;
	} osvw;

	/*
	 * Indicate whether the access faults on its page table in guest
	 * which is set when fix page fault and used to detect unhandeable
	 * instruction.
	 */
	bool write_fault_to_shadow_pgtable;

	/* set at EPT violation at this point */
	size_t exit_qualification;

	int pending_ioapic_eoi;
	int pending_external_vector;
};

struct kvm_arch_memory_slot {
	struct kvm_rmap_head *rmap;
	unsigned short *gfn_track[KVM_PAGE_TRACK_MAX];
};

/*
 * We use as the mode the number of bits allocated in the LDR for the
 * logical processor ID.  It happens that these are all powers of two.
 * This makes it is very easy to detect cases where the APICs are
 * configured for multiple modes; in that case, we cannot use the map and
 * hence cannot use kvm_irq_delivery_to_apic_fast either.
 */
#define GVM_APIC_MODE_XAPIC_CLUSTER          4
#define GVM_APIC_MODE_XAPIC_FLAT             8
#define GVM_APIC_MODE_X2APIC                16

struct kvm_apic_map {
	u8 mode;
	u32 max_apic_id;
	union {
		struct kvm_lapic *xapic_flat_map[8];
		struct kvm_lapic *xapic_cluster_map[16][4];
	};
	struct kvm_lapic *phys_map[];
};

struct kvm_arch {
	unsigned int n_used_mmu_pages;
	unsigned int n_requested_mmu_pages;
	unsigned int n_max_mmu_pages;
	unsigned int indirect_shadow_pages;
	size_t mmu_valid_gen;
	struct hlist_head mmu_page_hash[GVM_NUM_MMU_PAGES];
	/*
	 * Hash table of struct kvm_mmu_page.
	 */
	struct list_head active_mmu_pages;
	struct list_head zapped_obsolete_pages;
    struct kvm_page_track_notifier_node mmu_sp_tracker;
    struct kvm_page_track_notifier_head track_notifier_head;

	struct kvm_pic *vpic;
	struct kvm_ioapic *vioapic;
	struct kvm_pit *vpit;
	atomic_t vapics_in_nmi_mode;
	struct mutex apic_map_lock;
	struct kvm_apic_map *apic_map;

	unsigned int tss_addr;
	bool apic_access_page_done;

	gpa_t wall_clock;

	bool ept_identity_pagetable_done;
	gpa_t ept_identity_map_addr;

	size_t irq_sources_bitmap;
	raw_spinlock_t tsc_write_lock;

	u64 master_kernel_ns;

	/* reads protected by irq_srcu, writes by irq_lock */
	struct hlist_head mask_notifier_list;

	#ifdef CONFIG_GVM_MMU_AUDIT
	int audit_point;
	#endif

	bool boot_vcpu_runs_old_kvmclock;
	u32 bsp_vcpu_id;

	u64 disabled_quirks;

	u8 nr_reserved_ioapic_pins;

	bool disabled_lapic_found;

	/* Struct members for AVIC */
	u32 avic_vm_id;
	u32 ldr_mode;
	struct page *avic_logical_id_table_page;
	struct page *avic_physical_id_table_page;
	struct hlist_node hnode;

	bool x2apic_format;
	bool x2apic_broadcast_quirk_disabled;
};

struct kvm_vm_stat {
	ulong mmu_shadow_zapped;
	ulong mmu_pte_write;
	ulong mmu_pte_updated;
	ulong mmu_pde_zapped;
	ulong mmu_flooded;
	ulong mmu_recycled;
	ulong mmu_cache_miss;
	ulong mmu_unsync;
	ulong remote_tlb_flush;
	ulong lpages;
};

struct kvm_vcpu_stat {
	u64 pf_fixed;
	u64 pf_guest;
	u64 tlb_flush;
	u64 invlpg;

	u64 exits;
	u64 io_exits;
	u64 mmio_exits;
	u64 signal_exits;
	u64 irq_window_exits;
	u64 nmi_window_exits;
	u64 halt_exits;
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 request_irq_exits;
	u64 irq_exits;
	u64 host_state_reload;
	u64 efer_reload;
	u64 insn_emulation;
	u64 insn_emulation_fail;
	u64 hypercalls;
	u64 irq_injections;
	u64 nmi_injections;
};

struct x86_instruction_info;

struct msr_data {
	bool host_initiated;
	u32 index;
	u64 data;
};

struct kvm_lapic_irq {
	u32 vector;
	u16 delivery_mode;
	u16 dest_mode;
	bool level;
	u16 trig_mode;
	u32 shorthand;
	u32 dest_id;
	bool msi_redir_hint;
};

struct kvm_x86_ops {
	int (*cpu_has_kvm_support)(void);          /* __init */
	int (*disabled_by_bios)(void);             /* __init */
	int (*hardware_enable)(void);
	void (*hardware_disable)(void);
	void (*check_processor_compatibility)(void *rtn);
	int (*hardware_setup)(void);               /* __init */
	void (*hardware_unsetup)(void);            /* __exit */
	bool (*cpu_has_accelerated_tpr)(void);
	bool (*cpu_has_high_real_mode_segbase)(void);
	void (*cpuid_update)(struct kvm_vcpu *vcpu);

	int (*vm_init)(struct kvm *kvm);
	void (*vm_destroy)(struct kvm *kvm);

	/* Create, but do not attach this VCPU */
	struct kvm_vcpu *(*vcpu_create)(struct kvm *kvm, unsigned id);
	void (*vcpu_free)(struct kvm_vcpu *vcpu);
	void (*vcpu_reset)(struct kvm_vcpu *vcpu, bool init_event);

	void (*save_host_state)(struct kvm_vcpu *vcpu);
	void (*load_host_state)(struct kvm_vcpu *vcpu);
	void (*vcpu_load)(struct kvm_vcpu *vcpu, int cpu);
	void (*vcpu_put)(struct kvm_vcpu *vcpu);

	void (*update_bp_intercept)(struct kvm_vcpu *vcpu);
	int (*get_msr)(struct kvm_vcpu *vcpu, struct msr_data *msr);
	int (*set_msr)(struct kvm_vcpu *vcpu, struct msr_data *msr);
	u64 (*get_segment_base)(struct kvm_vcpu *vcpu, int seg);
	void (*get_segment)(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
	int (*get_cpl)(struct kvm_vcpu *vcpu);
	void (*set_segment)(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
	void (*get_cs_db_l_bits)(struct kvm_vcpu *vcpu, int *db, int *l);
	void (*decache_cr0_guest_bits)(struct kvm_vcpu *vcpu);
	void (*decache_cr3)(struct kvm_vcpu *vcpu);
	void (*decache_cr4_guest_bits)(struct kvm_vcpu *vcpu);
	void (*set_cr0)(struct kvm_vcpu *vcpu, size_t cr0);
	void (*set_cr3)(struct kvm_vcpu *vcpu, size_t cr3);
	int (*set_cr4)(struct kvm_vcpu *vcpu, size_t cr4);
	void (*set_efer)(struct kvm_vcpu *vcpu, u64 efer);
	void (*get_idt)(struct kvm_vcpu *vcpu, struct desc_ptr *dt);
	void (*set_idt)(struct kvm_vcpu *vcpu, struct desc_ptr *dt);
	void (*get_gdt)(struct kvm_vcpu *vcpu, struct desc_ptr *dt);
	void (*set_gdt)(struct kvm_vcpu *vcpu, struct desc_ptr *dt);
	u64 (*get_dr6)(struct kvm_vcpu *vcpu);
	void (*set_dr6)(struct kvm_vcpu *vcpu, size_t value);
	void (*sync_dirty_debug_regs)(struct kvm_vcpu *vcpu);
	void (*set_dr7)(struct kvm_vcpu *vcpu, size_t value);
	void (*cache_reg)(struct kvm_vcpu *vcpu, enum kvm_reg reg);
	size_t (*get_rflags)(struct kvm_vcpu *vcpu);
	void (*set_rflags)(struct kvm_vcpu *vcpu, size_t rflags);

	void (*tlb_flush)(struct kvm_vcpu *vcpu);

	void (*run)(struct kvm_vcpu *vcpu);
	int (*handle_exit)(struct kvm_vcpu *vcpu);
	void (*skip_emulated_instruction)(struct kvm_vcpu *vcpu);
	void (*set_interrupt_shadow)(struct kvm_vcpu *vcpu, int mask);
	u32 (*get_interrupt_shadow)(struct kvm_vcpu *vcpu);
	void (*patch_hypercall)(struct kvm_vcpu *vcpu,
				unsigned char *hypercall_addr);
	void (*set_irq)(struct kvm_vcpu *vcpu);
	void (*set_nmi)(struct kvm_vcpu *vcpu);
	void (*queue_exception)(struct kvm_vcpu *vcpu, unsigned nr,
				bool has_error_code, u32 error_code,
				bool reinject);
	void (*cancel_injection)(struct kvm_vcpu *vcpu);
	int (*interrupt_allowed)(struct kvm_vcpu *vcpu);
	int (*nmi_allowed)(struct kvm_vcpu *vcpu);
	bool (*get_nmi_mask)(struct kvm_vcpu *vcpu);
	void (*set_nmi_mask)(struct kvm_vcpu *vcpu, bool masked);
	void (*enable_nmi_window)(struct kvm_vcpu *vcpu);
	void (*enable_irq_window)(struct kvm_vcpu *vcpu);
	void (*update_cr8_intercept)(struct kvm_vcpu *vcpu, int tpr, int irr);
	bool (*get_enable_apicv)(void);
	void (*refresh_apicv_exec_ctrl)(struct kvm_vcpu *vcpu);
	void (*hwapic_irr_update)(struct kvm_vcpu *vcpu, int max_irr);
	void (*hwapic_isr_update)(struct kvm_vcpu *vcpu, int isr);
	void (*load_eoi_exitmap)(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap);
	void (*set_virtual_x2apic_mode)(struct kvm_vcpu *vcpu, bool set);
	void (*set_apic_access_page_addr)(struct kvm_vcpu *vcpu, hpa_t hpa);
	void (*deliver_posted_interrupt)(struct kvm_vcpu *vcpu, int vector);
	int (*set_tss_addr)(struct kvm *kvm, unsigned int addr);
	int (*get_tdp_level)(void);
	u64 (*get_mt_mask)(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio);
	int (*get_lpage_level)(void);
	bool (*rdtscp_supported)(void);
	bool (*invpcid_supported)(void);

	void (*set_tdp_cr3)(struct kvm_vcpu *vcpu, size_t cr3);

	void (*set_supported_cpuid)(u32 func, struct kvm_cpuid_entry *entry);

	bool (*has_wbinvd_exit)(void);

	void (*write_tsc_offset)(struct kvm_vcpu *vcpu, u64 offset);

	void (*get_exit_info)(struct kvm_vcpu *vcpu, u64 *info1, u64 *info2);

	int (*check_intercept)(struct kvm_vcpu *vcpu,
			       struct x86_instruction_info *info,
			       enum x86_intercept_stage stage);
	void (*handle_external_intr)(struct kvm_vcpu *vcpu);
	bool (*mpx_supported)(void);
	bool (*xsaves_supported)(void);

	int (*check_nested_events)(struct kvm_vcpu *vcpu, bool external_intr);

	/*
	 * Arch-specific dirty logging hooks. These hooks are only supposed to
	 * be valid if the specific arch has hardware-accelerated dirty logging
	 * mechanism. Currently only for PML on VMX.
	 *
	 *  - slot_enable_log_dirty:
	 *	called when enabling log dirty mode for the slot.
	 *  - slot_disable_log_dirty:
	 *	called when disabling log dirty mode for the slot.
	 *	also called when slot is created with log dirty disabled.
	 *  - flush_log_dirty:
	 *	called before reporting dirty_bitmap to userspace.
	 *  - enable_log_dirty_pt_masked:
	 *	called when reenabling log dirty for the GFNs in the mask after
	 *	corresponding bits are cleared in slot->dirty_bitmap.
	 */
	void (*slot_enable_log_dirty)(struct kvm *kvm,
				      struct kvm_memory_slot *slot);
	void (*slot_disable_log_dirty)(struct kvm *kvm,
				       struct kvm_memory_slot *slot);
	void (*flush_log_dirty)(struct kvm *kvm);
	void (*enable_log_dirty_pt_masked)(struct kvm *kvm,
					   struct kvm_memory_slot *slot,
					   gfn_t offset, size_t mask);
	/* pmu operations of sub-arch */
	const struct kvm_pmu_ops *pmu_ops;

	void (*vcpu_blocking)(struct kvm_vcpu *vcpu);
	void (*vcpu_unblocking)(struct kvm_vcpu *vcpu);

	void (*apicv_post_state_restore)(struct kvm_vcpu *vcpu);
};

extern struct kvm_x86_ops *kvm_x86_ops;

int kvm_mmu_module_init(void);
void kvm_mmu_module_exit(void);

void kvm_mmu_destroy(struct kvm_vcpu *vcpu);
int kvm_mmu_create(struct kvm_vcpu *vcpu);
void kvm_mmu_setup(struct kvm_vcpu *vcpu);
void kvm_mmu_init_vm(struct kvm *kvm);
void kvm_mmu_uninit_vm(struct kvm *kvm);
void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
		u64 dirty_mask, u64 nx_mask, u64 x_mask, u64 p_mask);

void kvm_mmu_reset_context(struct kvm_vcpu *vcpu);
void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      struct kvm_memory_slot *memslot);
void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot);
void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
				   struct kvm_memory_slot *memslot);
void kvm_mmu_slot_set_dirty(struct kvm *kvm,
			    struct kvm_memory_slot *memslot);
void kvm_mmu_clear_dirty_pt_masked(struct kvm *kvm,
				   struct kvm_memory_slot *slot,
				   gfn_t gfn_offset, size_t mask);
void kvm_mmu_zap_all(struct kvm *kvm);
void kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, struct kvm_memslots *slots);
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm);
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages);

int load_pdptrs(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu, size_t cr3);

int emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
			  const void *val, int bytes);

struct kvm_irq_mask_notifier {
	void (*func)(struct kvm_irq_mask_notifier *kimn, bool masked);
	int irq;
	struct hlist_node link;
};

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn);
void kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
				      struct kvm_irq_mask_notifier *kimn);
void kvm_fire_mask_notifiers(struct kvm *kvm, unsigned irqchip, unsigned pin,
			     bool mask);

extern bool tdp_enabled;

enum emulation_result {
	EMULATE_DONE,         /* no further processing */
	EMULATE_USER_EXIT,    /* kvm_run ready for userspace exit */
	EMULATE_FAIL,         /* can't emulate this instruction */
};

#define EMULTYPE_NO_DECODE	    (1 << 0)
#define EMULTYPE_TRAP_UD	    (1 << 1)
#define EMULTYPE_SKIP		    (1 << 2)
#define EMULTYPE_RETRY		    (1 << 3)
#define EMULTYPE_NO_REEXECUTE	    (1 << 4)
int x86_emulate_instruction(struct kvm_vcpu *vcpu, size_t cr2,
			    int emulation_type, void *insn, int insn_len);

static inline int emulate_instruction(struct kvm_vcpu *vcpu,
			int emulation_type)
{
	return x86_emulate_instruction(vcpu, 0, emulation_type, NULL, 0);
}

void kvm_enable_efer_bits(u64);
bool kvm_valid_efer(struct kvm_vcpu *vcpu, u64 efer);
int kvm_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr);
int kvm_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr);

struct x86_emulate_ctxt;

int kvm_fast_pio_out(struct kvm_vcpu *vcpu, int size, unsigned short port);
void kvm_emulate_cpuid(struct kvm_vcpu *vcpu);
int kvm_emulate_halt(struct kvm_vcpu *vcpu);
int kvm_vcpu_halt(struct kvm_vcpu *vcpu);
int kvm_emulate_wbinvd(struct kvm_vcpu *vcpu);

void kvm_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg);
int kvm_load_segment_descriptor(struct kvm_vcpu *vcpu, u16 selector, int seg);
void kvm_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector);

int kvm_task_switch(struct kvm_vcpu *vcpu, u16 tss_selector, int idt_index,
		    int reason, bool has_error_code, u32 error_code);

int kvm_set_cr0(struct kvm_vcpu *vcpu, size_t cr0);
int kvm_set_cr3(struct kvm_vcpu *vcpu, size_t cr3);
int kvm_set_cr4(struct kvm_vcpu *vcpu, size_t cr4);
int kvm_set_cr8(struct kvm_vcpu *vcpu, size_t cr8);
int kvm_set_dr(struct kvm_vcpu *vcpu, int dr, size_t val);
int kvm_get_dr(struct kvm_vcpu *vcpu, int dr, size_t *val);
size_t kvm_get_cr8(struct kvm_vcpu *vcpu);
void kvm_lmsw(struct kvm_vcpu *vcpu, size_t msw);
void kvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l);
int kvm_set_xcr(struct kvm_vcpu *vcpu, u32 index, u64 xcr);

int kvm_get_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr);
int kvm_set_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr);

size_t kvm_get_rflags(struct kvm_vcpu *vcpu);
void kvm_set_rflags(struct kvm_vcpu *vcpu, size_t rflags);
bool kvm_rdpmc(struct kvm_vcpu *vcpu);

void kvm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr);
void kvm_queue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, u32 error_code);
void kvm_requeue_exception(struct kvm_vcpu *vcpu, unsigned nr);
void kvm_requeue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, u32 error_code);
void kvm_inject_page_fault(struct kvm_vcpu *vcpu, struct x86_exception *fault);
int kvm_read_guest_page_mmu(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			    gfn_t gfn, void *data, int offset, int len,
			    u32 access);
bool kvm_require_cpl(struct kvm_vcpu *vcpu, int required_cpl);
bool kvm_require_dr(struct kvm_vcpu *vcpu, int dr);

static inline int __kvm_irq_line_state(size_t *irq_state,
				       int irq_source_id, int level)
{
	/* Logical OR for level trig interrupt */
	if (level)
		__set_bit(irq_source_id, irq_state);
	else
		__clear_bit(irq_source_id, irq_state);

	return !!(*irq_state);
}

int kvm_pic_set_irq(struct kvm_pic *pic, int irq, int irq_source_id, int level);
void kvm_pic_clear_all(struct kvm_pic *pic, int irq_source_id);

void kvm_inject_nmi(struct kvm_vcpu *vcpu);

int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn);
int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva);
void __kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu);
int kvm_mmu_load(struct kvm_vcpu *vcpu);
void kvm_mmu_unload(struct kvm_vcpu *vcpu);
void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu);
gpa_t translate_nested_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
			   struct x86_exception *exception);
gpa_t kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva,
			      struct x86_exception *exception);
gpa_t kvm_mmu_gva_to_gpa_fetch(struct kvm_vcpu *vcpu, gva_t gva,
			       struct x86_exception *exception);
gpa_t kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva,
			       struct x86_exception *exception);
gpa_t kvm_mmu_gva_to_gpa_system(struct kvm_vcpu *vcpu, gva_t gva,
				struct x86_exception *exception);

void kvm_vcpu_deactivate_apicv(struct kvm_vcpu *vcpu);

int kvm_emulate_hypercall(struct kvm_vcpu *vcpu);

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t gva, u32 error_code,
		       void *insn, int insn_len);
void kvm_mmu_invlpg(struct kvm_vcpu *vcpu, gva_t gva);
void kvm_mmu_new_cr3(struct kvm_vcpu *vcpu);

void kvm_enable_tdp(void);
void kvm_disable_tdp(void);

static inline gpa_t translate_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
				  struct x86_exception *exception)
{
	_CRT_UNUSED(vcpu);
	_CRT_UNUSED(access);
	_CRT_UNUSED(exception);
	return gpa;
}

static inline struct kvm_mmu_page *page_header(hpa_t shadow_page)
{
	struct page *page = (struct page *)pfn_to_page(shadow_page >> PAGE_SHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

static inline u16 kvm_read_ldt(void)
{
	return gvm_read_ldt();
}

static inline void kvm_load_ldt(u16 sel)
{
	gvm_load_ldt(sel);
}

#ifdef CONFIG_X86_64
static inline size_t read_msr(unsigned int msr)
{
	u64 value = 0;

	rdmsrl(msr, value);
	return value;
}
#endif

static inline u32 get_rdx_init_val(void)
{
	return 0x600; /* P6 family */
}

static inline void kvm_inject_gp(struct kvm_vcpu *vcpu, u32 error_code)
{
	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
}

static inline u64 get_canonical(u64 la)
{
	return ((int64_t)la << 16) >> 16;
}

static inline bool is_noncanonical_address(u64 la)
{
#ifdef CONFIG_X86_64
	return get_canonical(la) != la;
#else
	return false;
#endif
}

#define TSS_IOPB_BASE_OFFSET 0x66
#define TSS_BASE_SIZE 0x68
#define TSS_IOPB_SIZE (65536 / 8)
#define TSS_REDIRECTION_SIZE (256 / 8)
#define RMODE_TSS_SIZE							\
	(TSS_BASE_SIZE + TSS_REDIRECTION_SIZE + TSS_IOPB_SIZE + 1)

enum {
	TASK_SWITCH_CALL = 0,
	TASK_SWITCH_IRET = 1,
	TASK_SWITCH_JMP = 2,
	TASK_SWITCH_GATE = 3,
};

#define HF_GIF_MASK		(1 << 0)
#define HF_HIF_MASK		(1 << 1)
#define HF_VINTR_MASK		(1 << 2)
#define HF_NMI_MASK		(1 << 3)
#define HF_IRET_MASK		(1 << 4)
#define HF_GUEST_MASK		(1 << 5) /* VCPU is in guest-mode */
#define HF_SMM_MASK		(1 << 6)
#define HF_SMM_INSIDE_NMI_MASK	(1 << 7)

#define __GVM_VCPU_MULTIPLE_ADDRESS_SPACE
#define GVM_ADDRESS_SPACE_NUM 2

#define kvm_arch_vcpu_memslots_id(vcpu) ((vcpu)->arch.hflags & HF_SMM_MASK ? 1 : 0)
#define kvm_memslots_for_spte_role(kvm, role) __kvm_memslots(kvm, (role).smm)

#define GVM_ARCH_WANT_MMU_NOTIFIER
int kvm_unmap_hva(struct kvm *kvm, size_t hva);
int kvm_unmap_hva_range(struct kvm *kvm, size_t start, size_t end);
int kvm_age_hva(struct kvm *kvm, size_t start, size_t end);
int kvm_test_age_hva(struct kvm *kvm, size_t hva);
void kvm_set_spte_hva(struct kvm *kvm, size_t hva, pte_t pte);
int kvm_cpu_has_injectable_intr(struct kvm_vcpu *v);
int kvm_cpu_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu);
int kvm_cpu_get_interrupt(struct kvm_vcpu *v);
void kvm_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event);
void kvm_vcpu_reload_apic_access_page(struct kvm_vcpu *vcpu);
void kvm_arch_mmu_notifier_invalidate_page(struct kvm *kvm,
					   size_t address);

void kvm_define_shared_msr(unsigned index, u32 msr);
int kvm_set_shared_msr(unsigned index, u64 val, u64 mask);

u64 kvm_scale_tsc(struct kvm_vcpu *vcpu, u64 tsc);
u64 kvm_read_l1_tsc(struct kvm_vcpu *vcpu, u64 host_tsc);

size_t kvm_get_linear_rip(struct kvm_vcpu *vcpu);
bool kvm_is_linear_rip(struct kvm_vcpu *vcpu, size_t linear_rip);

void kvm_make_scan_ioapic_request(struct kvm *kvm);

void kvm_complete_insn_gp(struct kvm_vcpu *vcpu, int err);

int kvm_is_in_guest(void);

int __x86_set_memory_region(struct kvm *kvm, int id, gpa_t gpa, u32 size);
int x86_set_memory_region(struct kvm *kvm, int id, gpa_t gpa, u32 size);
bool kvm_vcpu_is_reset_bsp(struct kvm_vcpu *vcpu);
bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu);

bool kvm_intr_is_single_vcpu(struct kvm *kvm, struct kvm_lapic_irq *irq,
			     struct kvm_vcpu **dest_vcpu);

void kvm_set_msi_irq(struct kvm *kvm, struct kvm_kernel_irq_routing_entry *e,
		     struct kvm_lapic_irq *irq);

static inline void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_ops->vcpu_blocking)
		kvm_x86_ops->vcpu_blocking(vcpu);
}

static inline void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_ops->vcpu_unblocking)
		kvm_x86_ops->vcpu_unblocking(vcpu);
}

static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu)
{
	_CRT_UNUSED(vcpu);
}

static inline int kvm_cpu_get_apicid(int mps_cpu)
{
#ifdef CONFIG_X86_LOCAL_APIC
	return __default_cpu_present_to_apicid(mps_cpu);
#else
	_CRT_UNUSED(mps_cpu);
	WARN_ON_ONCE(1);
	return BAD_APICID;
#endif
}

#endif /* _ASM_X86_KVM_HOST_H */
