/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_KVM_H
#define __LINUX_KVM_H

/*
 * Userspace interface for /dev/kvm - kernel based virtual machine
 *
 * Note: you must update AEHD_API_VERSION if you change this interface.
 */

#include <uapi/asm/kvm.h>
#include <aehd_types.h>
#include <aehd_ver.h>

/* for AEHD_CREATE_MEMORY_REGION */
struct kvm_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
};

/* for AEHD_SET_USER_MEMORY_REGION */
struct kvm_userspace_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
	__u64 userspace_addr; /* start of the userspace allocated memory */
};

/*
 * The bit 0 ~ bit 15 of kvm_memory_region::flags are visible for userspace,
 * other bits are reserved for kvm internal use which are defined in
 * include/linux/kvm_host.h.
 */
#define AEHD_MEM_LOG_DIRTY_PAGES	(1ULL << 0)
#define AEHD_MEM_READONLY	(1ULL << 1)

/* for AEHD_IRQ_LINE */
struct kvm_irq_level {
	/*
	 * ACPI gsi notion of irq.
	 * For IA-64 (APIC model) IOAPIC0: irq 0-23; IOAPIC1: irq 24-47..
	 * For X86 (standard AT mode) PIC0/1: irq 0-15. IOAPIC0: 0-23..
	 * For ARM: See Documentation/virtual/kvm/api.txt
	 */
	union {
		__u32 irq;
		__s32 status;
	};
	__u32 level;
};


struct kvm_irqchip {
	__u32 chip_id;
	__u32 pad;
        union {
		char dummy[512];  /* reserving space */
		struct kvm_pic_state pic;
		struct kvm_ioapic_state ioapic;
	} chip;
};

#define AEHD_EXIT_UNKNOWN          0
#define AEHD_EXIT_EXCEPTION        1
#define AEHD_EXIT_IO               2
#define AEHD_EXIT_HYPERCALL        3
#define AEHD_EXIT_DEBUG            4
#define AEHD_EXIT_HLT              5
#define AEHD_EXIT_MMIO             6
#define AEHD_EXIT_IRQ_WINDOW_OPEN  7
#define AEHD_EXIT_SHUTDOWN         8
#define AEHD_EXIT_FAIL_ENTRY       9
#define AEHD_EXIT_INTR             10
#define AEHD_EXIT_SET_TPR          11
#define AEHD_EXIT_TPR_ACCESS       12
#define AEHD_EXIT_NMI              16
#define AEHD_EXIT_INTERNAL_ERROR   17
#define AEHD_EXIT_OSI              18
#define AEHD_EXIT_PAPR_HCALL	  19
#define AEHD_EXIT_WATCHDOG         21
#define AEHD_EXIT_EPR              23
#define AEHD_EXIT_SYSTEM_EVENT     24
#define AEHD_EXIT_IOAPIC_EOI       26

/* For AEHD_EXIT_INTERNAL_ERROR */
/* Emulate instruction failed. */
#define AEHD_INTERNAL_ERROR_EMULATION	1
/* Encounter unexpected simultaneous exceptions. */
#define AEHD_INTERNAL_ERROR_SIMUL_EX	2
/* Encounter unexpected vm-exit due to delivery event. */
#define AEHD_INTERNAL_ERROR_DELIVERY_EV	3

/* for AEHD_RUN, returned by mmap(vcpu_fd, offset=0) */
struct kvm_run {
	/* in */
	__u8 request_interrupt_window;
	__u8 user_event_pending;
	__u8 padding1[6];

	/* out */
	__u32 exit_reason;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u16 flags;

	/* in (pre_kvm_run), out (post_kvm_run) */
	__u64 cr8;
	__u64 apic_base;

	union {
		/* AEHD_EXIT_UNKNOWN */
		struct {
			__u64 hardware_exit_reason;
		} hw;
		/* AEHD_EXIT_FAIL_ENTRY */
		struct {
			__u64 hardware_entry_failure_reason;
		} fail_entry;
		/* AEHD_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* AEHD_EXIT_IO */
		struct {
#define AEHD_EXIT_IO_IN  0
#define AEHD_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u16 port;
			__u32 count;
			__u64 data_offset; /* relative to kvm_run start */
		} io;
		/* AEHD_EXIT_DEBUG */
		struct {
			struct kvm_debug_exit_arch arch;
		} debug;
		/* AEHD_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
		/* AEHD_EXIT_HYPERCALL */
		struct {
			__u64 nr;
			__u64 args[6];
			__u64 ret;
			__u32 longmode;
			__u32 pad;
		} hypercall;
		/* AEHD_EXIT_TPR_ACCESS */
		struct {
			__u64 rip;
			__u32 is_write;
			__u32 pad;
		} tpr_access;
		/* AEHD_EXIT_INTERNAL_ERROR */
		struct {
			__u32 suberror;
			/* Available with AEHD_CAP_INTERNAL_ERROR_DATA: */
			__u32 ndata;
			__u64 data[16];
		} internal;
		/* AEHD_EXIT_OSI */
		struct {
			__u64 gprs[32];
		} osi;
		/* AEHD_EXIT_PAPR_HCALL */
		struct {
			__u64 nr;
			__u64 ret;
			__u64 args[9];
		} papr_hcall;
		/* AEHD_EXIT_EPR */
		struct {
			__u32 epr;
		} epr;
		/* AEHD_EXIT_SYSTEM_EVENT */
		struct {
#define AEHD_SYSTEM_EVENT_SHUTDOWN       1
#define AEHD_SYSTEM_EVENT_RESET          2
#define AEHD_SYSTEM_EVENT_CRASH          3
			__u32 type;
			__u64 flags;
		} system_event;
		/* AEHD_EXIT_IOAPIC_EOI */
		struct {
			__u8 vector;
		} eoi;
		/* Fix the size of the union. */
		char padding[256];
	};

	/*
	 * shared registers between kvm and userspace.
	 * kvm_valid_regs specifies the register classes set by the host
	 * kvm_dirty_regs specified the register classes dirtied by userspace
	 * struct kvm_sync_regs is architecture specific, as well as the
	 * bits for kvm_valid_regs and kvm_dirty_regs
	 */
	__u64 kvm_valid_regs;
	__u64 kvm_dirty_regs;
	union {
		struct kvm_sync_regs regs;
		char padding[2048];
	} s;
};

/* for AEHD_TRANSLATE */
struct kvm_translation {
	/* in */
	__u64 linear_address;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
	__u8  pad[5];
};

/* for AEHD_INTERRUPT */
struct kvm_interrupt {
	/* in */
	__u32 irq;
};

/* for AEHD_GET_DIRTY_LOG */
struct kvm_dirty_log {
	__u32 slot;
	__u32 padding1;
	union {
		void __user *dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

/* for AEHD_TPR_ACCESS_REPORTING */
struct kvm_tpr_access_ctl {
	__u32 enabled;
	__u32 flags;
	__u32 reserved[8];
};

/* for AEHD_SET_VAPIC_ADDR */
struct kvm_vapic_addr {
	__u64 vapic_addr;
};

/* for AEHD_SET_MP_STATE */

/* not all states are valid on all architectures */
#define AEHD_MP_STATE_RUNNABLE          0
#define AEHD_MP_STATE_UNINITIALIZED     1
#define AEHD_MP_STATE_INIT_RECEIVED     2
#define AEHD_MP_STATE_HALTED            3
#define AEHD_MP_STATE_SIPI_RECEIVED     4
#define AEHD_MP_STATE_STOPPED           5
#define AEHD_MP_STATE_CHECK_STOP        6
#define AEHD_MP_STATE_OPERATING         7
#define AEHD_MP_STATE_LOAD              8

struct kvm_mp_state {
	__u32 mp_state;
};

/* for AEHD_SET_GUEST_DEBUG */

#define AEHD_GUESTDBG_ENABLE		0x00000001
#define AEHD_GUESTDBG_SINGLESTEP		0x00000002

struct kvm_guest_debug {
	__u32 control;
	__u32 pad;
	struct kvm_guest_debug_arch arch;
};

/* for AEHD_ENABLE_CAP */
struct kvm_enable_cap {
	/* in */
	__u32 cap;
	__u32 flags;
	__u64 args[4];
	__u8  pad[64];
};

#define KVMIO 0xAE

/*
 * ioctls for /dev/kvm fds:
 */
#define AEHD_GET_API_VERSION       _IO(KVMIO,   0x00)
#define AEHD_CREATE_VM             _IO(KVMIO,   0x01) /* returns a VM fd */
#define AEHD_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct kvm_msr_list)
/*
 * Check if a kvm extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
#define AEHD_CHECK_EXTENSION       _IO(KVMIO,   0x03)
/*
 * Get size for mmap(vcpu_fd)
 */
#define AEHD_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */
#define AEHD_GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct kvm_cpuid)
#define AEHD_GET_EMULATED_CPUID	  _IOWR(KVMIO, 0x09, struct kvm_cpuid)
/*
 * Extension capability list.
 */
#define AEHD_CAP_IRQCHIP	  0
#define AEHD_CAP_HLT	  1
#define AEHD_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define AEHD_CAP_VAPIC 6
#define AEHD_CAP_NR_VCPUS 9       /* returns recommended max vcpus per vm */
#define AEHD_CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
#define AEHD_CAP_NOP_IO_DELAY 12
#define AEHD_CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
#define AEHD_CAP_USER_NMI 22
#ifdef __AEHD_HAVE_GUEST_DEBUG
#define AEHD_CAP_SET_GUEST_DEBUG 23
#endif
#define AEHD_CAP_REINJECT_CONTROL 24
#define AEHD_CAP_IRQ_ROUTING 25
#define AEHD_CAP_SET_BOOT_CPU_ID 34
#define AEHD_CAP_SET_IDENTITY_MAP_ADDR 37
#ifdef __AEHD_HAVE_VCPU_EVENTS
#define AEHD_CAP_VCPU_EVENTS 41
#endif
#define AEHD_CAP_PCI_SEGMENT 47
#define AEHD_CAP_INTR_SHADOW 49
#ifdef __AEHD_HAVE_DEBUGREGS
#define AEHD_CAP_DEBUGREGS 50
#endif
#define AEHD_CAP_X86_ROBUST_SINGLESTEP 51
#define AEHD_CAP_ENABLE_CAP 54
#ifdef __AEHD_HAVE_XSAVE
#define AEHD_CAP_XSAVE 55
#endif
#ifdef __AEHD_HAVE_XCRS
#define AEHD_CAP_XCRS 56
#endif
#define AEHD_CAP_MAX_VCPUS 66       /* returns max vcpus per vm */
#define AEHD_CAP_SW_TLB 69
#define AEHD_CAP_SYNC_REGS 74
#define AEHD_CAP_SIGNAL_MSI 77
#define AEHD_CAP_READONLY_MEM 81
#define AEHD_CAP_EXT_EMUL_CPUID 95
#define AEHD_CAP_IOAPIC_POLARITY_IGNORED 97
#define AEHD_CAP_ENABLE_CAP_VM 98
#define AEHD_CAP_VM_ATTRIBUTES 101
#define AEHD_CAP_DISABLE_QUIRKS 116
#define AEHD_CAP_X86_SMM 117
#define AEHD_CAP_MULTI_ADDRESS_SPACE 118
#define AEHD_CAP_GUEST_DEBUG_HW_BPS 119
#define AEHD_CAP_GUEST_DEBUG_HW_WPS 120
#define AEHD_CAP_VCPU_ATTRIBUTES 127
#define AEHD_CAP_MAX_VCPU_ID 128

struct kvm_irq_routing_irqchip {
	__u32 irqchip;
	__u32 pin;
};

struct kvm_irq_routing_msi {
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
	union {
		__u32 pad;
		__u32 devid;
	};
};

struct kvm_irq_routing_hv_sint {
	__u32 vcpu;
	__u32 sint;
};

/* gsi routing entry types */
#define AEHD_IRQ_ROUTING_IRQCHIP 1
#define AEHD_IRQ_ROUTING_MSI 2

struct kvm_irq_routing_entry {
	__u32 gsi;
	__u32 type;
	__u32 flags;
	__u32 pad;
	union {
		struct kvm_irq_routing_irqchip irqchip;
		struct kvm_irq_routing_msi msi;
		struct kvm_irq_routing_hv_sint hv_sint;
		__u32 pad[8];
	} u;
};

struct kvm_irq_routing {
	__u32 nr;
	__u32 flags;
	struct kvm_irq_routing_entry entries[0];
};

/* For AEHD_CAP_SW_TLB */

#define AEHD_MMU_FSL_BOOKE_NOHV		0
#define AEHD_MMU_FSL_BOOKE_HV		1

struct kvm_config_tlb {
	__u64 params;
	__u64 array;
	__u32 mmu_type;
	__u32 array_len;
};

struct kvm_dirty_tlb {
	__u64 bitmap;
	__u32 num_dirty;
};

/* Available with AEHD_CAP_ONE_REG */

#define AEHD_REG_ARCH_MASK	0xff00000000000000ULL
#define AEHD_REG_GENERIC		0x0000000000000000ULL

/*
 * Architecture specific registers are to be defined in arch headers and
 * ORed with the arch identifier.
 */
#define AEHD_REG_X86		0x2000000000000000ULL

#define AEHD_REG_SIZE_SHIFT	52
#define AEHD_REG_SIZE_MASK	0x00f0000000000000ULL
#define AEHD_REG_SIZE_U8		0x0000000000000000ULL
#define AEHD_REG_SIZE_U16	0x0010000000000000ULL
#define AEHD_REG_SIZE_U32	0x0020000000000000ULL
#define AEHD_REG_SIZE_U64	0x0030000000000000ULL
#define AEHD_REG_SIZE_U128	0x0040000000000000ULL
#define AEHD_REG_SIZE_U256	0x0050000000000000ULL
#define AEHD_REG_SIZE_U512	0x0060000000000000ULL
#define AEHD_REG_SIZE_U1024	0x0070000000000000ULL

struct kvm_reg_list {
	__u64 n; /* number of regs */
	__u64 reg[0];
};

struct kvm_one_reg {
	__u64 id;
	__u64 addr;
};

#define AEHD_MSI_VALID_DEVID	(1U << 0)
struct kvm_msi {
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
	__u32 flags;
	__u32 devid;
	__u8  pad[12];
};

/*
 * ioctls for VM fds
 */
#define AEHD_SET_MEMORY_REGION     _IOW(KVMIO,  0x40, struct kvm_memory_region)
/*
 * AEHD_CREATE_VCPU receives as a parameter the vcpu slot, and returns
 * a vcpu fd.
 */
#define AEHD_CREATE_VCPU           _IO(KVMIO,   0x41)
#define AEHD_GET_DIRTY_LOG         _IOW(KVMIO,  0x42, struct kvm_dirty_log)
/* AEHD_SET_MEMORY_ALIAS is obsolete: */
#define AEHD_SET_MEMORY_ALIAS      _IOW(KVMIO,  0x43, struct kvm_memory_alias)
#define AEHD_SET_NR_MMU_PAGES      _IO(KVMIO,   0x44)
#define AEHD_GET_NR_MMU_PAGES      _IO(KVMIO,   0x45)
#define AEHD_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_userspace_memory_region)
#define AEHD_SET_TSS_ADDR          _IO(KVMIO,   0x47)
#define AEHD_SET_IDENTITY_MAP_ADDR _IOW(KVMIO,  0x48, __u64)
#define AEHD_KICK_VCPU             _IO(KVMIO,   0x49)

/* Device model IOC */
#define AEHD_CREATE_IRQCHIP        _IO(KVMIO,   0x60)
#define AEHD_GET_IRQCHIP           _IOWR(KVMIO, 0x62, struct kvm_irqchip)
#define AEHD_SET_IRQCHIP           _IOR(KVMIO,  0x63, struct kvm_irqchip)
#define AEHD_IRQ_LINE_STATUS       _IOWR(KVMIO, 0x67, struct kvm_irq_level)
#define AEHD_SET_GSI_ROUTING       _IOW(KVMIO,  0x6a, struct kvm_irq_routing)
#define AEHD_SET_BOOT_CPU_ID       _IO(KVMIO,   0x78)
/* Available with AEHD_CAP_SIGNAL_MSI */
#define AEHD_SIGNAL_MSI            _IOW(KVMIO,  0xa5, struct kvm_msi)

/*
 * ioctls for vcpu fds
 */
#define AEHD_RUN                   _IO(KVMIO,   0x80)
#define AEHD_VCPU_MMAP             _IO(KVMIO,   0x87)
#define AEHD_GET_REGS              _IOR(KVMIO,  0x81, struct kvm_regs)
#define AEHD_SET_REGS              _IOW(KVMIO,  0x82, struct kvm_regs)
#define AEHD_GET_SREGS             _IOR(KVMIO,  0x83, struct kvm_sregs)
#define AEHD_SET_SREGS             _IOW(KVMIO,  0x84, struct kvm_sregs)
#define AEHD_TRANSLATE             _IOWR(KVMIO, 0x85, struct kvm_translation)
#define AEHD_INTERRUPT             _IOW(KVMIO,  0x86, struct kvm_interrupt)
#define AEHD_GET_MSRS              _IOWR(KVMIO, 0x88, struct kvm_msrs)
#define AEHD_SET_MSRS              _IOW(KVMIO,  0x89, struct kvm_msrs)
#define AEHD_GET_FPU               _IOR(KVMIO,  0x8c, struct kvm_fpu)
#define AEHD_SET_FPU               _IOW(KVMIO,  0x8d, struct kvm_fpu)
#define AEHD_GET_LAPIC             _IOR(KVMIO,  0x8e, struct kvm_lapic_state)
#define AEHD_SET_LAPIC             _IOW(KVMIO,  0x8f, struct kvm_lapic_state)
#define AEHD_SET_CPUID             _IOW(KVMIO,  0x90, struct kvm_cpuid)
#define AEHD_GET_CPUID             _IOWR(KVMIO, 0x91, struct kvm_cpuid)
/* Available with AEHD_CAP_VAPIC */
#define AEHD_TPR_ACCESS_REPORTING  _IOWR(KVMIO, 0x92, struct kvm_tpr_access_ctl)
/* Available with AEHD_CAP_VAPIC */
#define AEHD_SET_VAPIC_ADDR        _IOW(KVMIO,  0x93, struct kvm_vapic_addr)
#define AEHD_GET_MP_STATE          _IOR(KVMIO,  0x98, struct kvm_mp_state)
#define AEHD_SET_MP_STATE          _IOW(KVMIO,  0x99, struct kvm_mp_state)
/* Available with AEHD_CAP_USER_NMI */
#define AEHD_NMI                   _IO(KVMIO,   0x9a)
/* Available with AEHD_CAP_SET_GUEST_DEBUG */
#define AEHD_SET_GUEST_DEBUG       _IOW(KVMIO,  0x9b, struct kvm_guest_debug)
/* Available with AEHD_CAP_VCPU_EVENTS */
#define AEHD_GET_VCPU_EVENTS       _IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
#define AEHD_SET_VCPU_EVENTS       _IOW(KVMIO,  0xa0, struct kvm_vcpu_events)
/* Available with AEHD_CAP_DEBUGREGS */
#define AEHD_GET_DEBUGREGS         _IOR(KVMIO,  0xa1, struct kvm_debugregs)
#define AEHD_SET_DEBUGREGS         _IOW(KVMIO,  0xa2, struct kvm_debugregs)
/*
 * vcpu version available with AEHD_ENABLE_CAP
 * vm version available with AEHD_CAP_ENABLE_CAP_VM
 */
#define AEHD_ENABLE_CAP            _IOW(KVMIO,  0xa3, struct kvm_enable_cap)
/* Available with AEHD_CAP_XSAVE */
#define AEHD_GET_XSAVE		  _IOR(KVMIO,  0xa4, struct kvm_xsave)
#define AEHD_SET_XSAVE		  _IOW(KVMIO,  0xa5, struct kvm_xsave)
/* Available with AEHD_CAP_XCRS */
#define AEHD_GET_XCRS		  _IOR(KVMIO,  0xa6, struct kvm_xcrs)
#define AEHD_SET_XCRS		  _IOW(KVMIO,  0xa7, struct kvm_xcrs)
/* Available with AEHD_CAP_SW_TLB */
#define AEHD_DIRTY_TLB		  _IOW(KVMIO,  0xaa, struct kvm_dirty_tlb)
/* Available with AEHD_CAP_X86_SMM */
#define AEHD_SMI                   _IO(KVMIO,   0xb7)

#define AEHD_X2APIC_API_USE_32BIT_IDS            (1ULL << 0)
#define AEHD_X2APIC_API_DISABLE_BROADCAST_QUIRK  (1ULL << 1)

#endif /* __LINUX_KVM_H */
