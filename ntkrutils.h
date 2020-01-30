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
#include <ntddk.h>
#include <intrin.h>
#include <gvm_types.h>
#include <string.h>
#include <dos.h>
#include <linux/list.h>
#include <uapi/asm/processor-flags.h>

// APC definitions (undocumented)
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(NTAPI *PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef
VOID
(NTAPI *PKKERNEL_ROUTINE)(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
	);

typedef
VOID
(NTAPI *PKRUNDOWN_ROUTINE) (
	_In_ PKAPC Apc
	);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
	);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
	);

// MSDN recommends the string in reverse order
#define GVM_POOL_TAG '_MVG'

// cpuid
static __forceinline void cpuid(unsigned int op,
	unsigned int *eax,
	unsigned int *ebx,
	unsigned int *ecx,
	unsigned int *edx)
{
	int cpuInfo[4];
	__cpuid(cpuInfo, op);
	*eax = cpuInfo[0];
	*ebx = cpuInfo[1];
	*ecx = cpuInfo[2];
	*edx = cpuInfo[3];
}

static __forceinline void cpuid_count(unsigned int op,
	unsigned int count,
	unsigned int *eax,
	unsigned int *ebx,
	unsigned int *ecx,
	unsigned int *edx)
{
	int cpuInfo[4];
	__cpuidex(cpuInfo, op, count);
	*eax = cpuInfo[0];
	*ebx = cpuInfo[1];
	*ecx = cpuInfo[2];
	*edx = cpuInfo[3];
}

static __inline unsigned int cpuid_eax(unsigned int op)
{
        unsigned int eax, ebx, ecx, edx;

        cpuid(op, &eax, &ebx, &ecx, &edx);

        return eax;
}

static __inline unsigned int cpuid_ebx(unsigned int op)
{
        unsigned int eax, ebx, ecx, edx;

        cpuid(op, &eax, &ebx, &ecx, &edx);

        return ebx;
}

static __inline unsigned int cpuid_ecx(unsigned int op)
{
        unsigned int eax, ebx, ecx, edx;

        cpuid(op, &eax, &ebx, &ecx, &edx);

        return ecx;
}

static __inline unsigned int cpuid_edx(unsigned int op)
{
        unsigned int eax, ebx, ecx, edx;

        cpuid(op, &eax, &ebx, &ecx, &edx);

        return edx;
}

static __forceinline unsigned int x86_family(unsigned int sig)
{
	unsigned int x86;

	x86 = (sig >> 8) & 0xf;

	if (x86 == 0xf)
		x86 += (sig >> 20) & 0xff;

	return x86;
}

static __forceinline unsigned int x86_cpuid_family(void)
{
	return x86_family(cpuid_eax(1));
}

static __forceinline unsigned int x86_model(unsigned int sig)
{
	unsigned int fam, model;

	fam = x86_family(sig);

	model = (sig >> 4) & 0xf;

	if (fam >= 0x6)
		model += ((sig >> 16) & 0xf) << 4;

	return model;
}

static __forceinline unsigned int x86_cpuid_model(void)
{
	return x86_model(cpuid_eax(1));
}

static __forceinline unsigned int x86_stepping(unsigned int sig)
{
	return sig & 0xf;
}

/*
 * cpu_has_vmx
 */
static __inline int cpu_has_vmx(void)
{
	size_t ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

/*
 * Memory Barriers
 */
#define smp_mb() _mm_mfence()
#define smp_rmb() _mm_lfence()
#define smp_wmb() _mm_sfence()
#define mb() _mm_mfence()
#define rmb() _mm_lfence()
#define wmb() _mm_sfence()
#define smp_mb__after_atomic() _mm_mfence();

// smp_processor_id
static __inline unsigned int raw_smp_processor_id(void)
{
	return KeGetCurrentProcessorNumberEx(NULL);
}

static __inline unsigned int smp_processor_id(void)
{
	return raw_smp_processor_id();
}

/*
 * cpu_get/put for ensure vmx safety
 */

struct cpu_getput_cxt {
	long count;
	KIRQL irql;
};

DECLARE_PER_CPU(struct cpu_getput_cxt, cpu_getput_cxt);

static __inline unsigned int get_cpu()
{
	KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
	unsigned int cpu = smp_processor_id();
	long newcount = InterlockedIncrement(&per_cpu(cpu_getput_cxt, cpu).count);

	if (newcount == 1)
		per_cpu(cpu_getput_cxt, cpu).irql = oldIrql;

	return cpu;
}

static __inline void put_cpu()
{
	unsigned int cpu = smp_processor_id();
	long newcount = InterlockedDecrement(&per_cpu(cpu_getput_cxt, cpu).count);
	BUG_ON(newcount < 0);
	if (newcount == 0) {
		KIRQL oldIrql = per_cpu(cpu_getput_cxt, cpu).irql;
		per_cpu(cpu_getput_cxt, cpu).irql = 0;
		KeLowerIrql(oldIrql);
	}
}

#define preempt_disable() KeRaiseIrqlToDpcLevel()
#define preempt_enable() KeLowerIrql(PASSIVE_LEVEL)

// msr access
static _forceinline void wrmsrl(unsigned int msr, u64 val)
{
	__writemsr(msr, val);
}

extern struct cpumask *cpu_online_mask;
extern unsigned int cpu_online_count;

/*
 * SpinLock Implementation
 * Compared with Windows Native Support, this implementation does not raise IRQL to DPC level.
 * KVM has nasty lock nesting that might work on Linux but not directly on Windows.
 */
struct spin_lock {
	volatile LONG lock;
};

typedef struct spin_lock spinlock_t;
typedef struct spin_lock raw_spinlock_t;

#define DEFINE_SPINLOCK(x) spinlock_t x
#define DECLARE_SPINLOCK(x) extern spinlock_t x
#define DEFINE_RAW_SPINLOCK(x) spinlock_t x
#define DECLARE_RAW_SPINLOCK(x) extern spinlock_t x

static __forceinline void spin_lock_init(spinlock_t *lock)
{
	lock->lock = 0;
}

extern __forceinline void __spin_lock(spinlock_t *lock);
static __forceinline void spin_lock(spinlock_t *lock)
{
	__spin_lock(lock);
}

static __forceinline void spin_unlock(spinlock_t *lock)
{
	lock->lock = 0;
}

static __forceinline void raw_spin_lock_init(spinlock_t *lock)
{
	spin_lock_init(lock);
}

static __forceinline void raw_spin_lock(spinlock_t *lock)
{
	spin_lock(lock);
}

static __forceinline void raw_spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}

/*
 Mutex Windows Implementation
 */
struct mutex
{
	FAST_MUTEX mutex;
};
typedef struct mutex mutex;

static __forceinline void mutex_init(struct mutex *lock)
{
	ExInitializeFastMutex(&lock->mutex);
}

static __forceinline void mutex_lock(struct mutex *lock)
{
	ExAcquireFastMutex(&lock->mutex);
}

static __forceinline void mutex_unlock(struct mutex *lock)
{
	ExReleaseFastMutex(&lock->mutex);
}

#define __KERNEL_CS 0x10
#define __KERNEL_DS 0x28
#define __KERNEL_SS 0x18
#define __KERNEL_FS 0x53

/*
 MSR access
 */
static __inline void __rdmsr(u32 index, u32 *low, u32 *high)
{
	u64 val = __readmsr(index);
	*low = (u32)val;
	*high = (u32)(val >> 32);
}

static __inline int __rdmsr_safe(u32 index, u32 *low, u32 *high)
{
	u64 val = 0;
	__try {
		val = __readmsr(index);
		*low = (u32)val;
		*high = (u32)(val >> 32);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
	return 0;
}

static __inline int __rdmsrl_safe(u32 index, u64 *val)
{
	__try {
		*val = __readmsr(index);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
	return 0;
}

static __inline u64 native_read_msr_safe(u32 index, int *err)
{
	u64 value = 0;
	*err = __rdmsrl_safe(index, &value);
	return value;
}

static __inline int __wrmsr_safe(u32 index, u32 low, u32 high)
{
	u64 val = (((u64)high) << 32) | low;
	__try {
		__writemsr(index, val);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
	return 0;
}

static __inline int __wrmsrl_safe(u32 index, u64 val)
{
	__try {
		__writemsr(index, val);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
	return 0;
}

static __inline int native_write_msr_safe(u32 index, u32 low, u32 high)
{
	return __wrmsr_safe(index, low, high);
}

#define rdmsr(a, b, c) __rdmsr(a, &b, &c)
#define rdmsr_safe(a, b, c)	__rdmsr_safe(a, b, c)
#define rdmsrl(a, b) b=__readmsr(a)
#define rdmsrl_safe(a, b) __rdmsrl_safe(a, b)

#define wrmsr(a,b) __writemsr(a,b)
#define wrmsrl(a,b) __writemsr(a,b)
#define wrmsr_safe(a, b, c) __wrmsr_safe(a, b, c)
#define wrmsrl_safe(a,b) __wrmsrl_safe(a,b)

/*
 Local Irq Disable
 */
static __forceinline void local_irq_disable(void)
{
	_disable();
}

static __forceinline void local_irq_enable(void)
{
	_enable();
}

/*
 Timer Stuffs
 */

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

union ktime 
{
	s64	tv64;
	struct {
	s32	nsec, sec;
	} tv;
};

typedef union ktime ktime_t;

#define KTIME_MAX			((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX			LONG_MAX

#pragma warning(disable : 4204)
static __forceinline ktime_t ktime_set(const long secs, const size_t nsecs)
{
#if 0
	if (unlikely(secs >= KTIME_SEC_MAX))
		return (ktime_t){ .tv64 = KTIME_MAX };
#endif
	return (ktime_t) { .tv64 = (s64)secs * NSEC_PER_SEC + (s64)nsecs };
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs) \
		(ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }

/* Add two ktime_t variables. res = lhs + rhs: */
#define ktime_add(lhs, rhs) \
		(ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
#define ktime_add_ns(kt, nsval) \
		(ktime_t){ .tv64 = (kt).tv64 + (nsval) }

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
#define ktime_sub_ns(kt, nsval) \
		(ktime_t){ .tv64 = (kt).tv64 - (nsval) }


/* Map the ktime_t to timespec conversion to ns_to_timespec function */
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)

/* Map the ktime_t to timeval conversion to ns_to_timeval function */
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)

/* Convert ktime_t to nanoseconds - NOP in the scalar storage format: */
#define ktime_to_ns(kt)			((kt).tv64)

static __forceinline int ktime_equal(const ktime_t cmp1, const ktime_t cmp2)
{
	return cmp1.tv64 == cmp2.tv64;
}

/**
 * ktime_compare - Compares two ktime_t variables for less, greater or equal
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Returns ...
 *   cmp1  < cmp2: return <0
 *   cmp1 == cmp2: return 0
 *   cmp1  > cmp2: return >0
 */
static __forceinline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
	if (cmp1.tv64 < cmp2.tv64)
		return -1;
	if (cmp1.tv64 > cmp2.tv64)
		return 1;
	return 0;
}

static __forceinline ktime_t ktime_add_us(const ktime_t kt, const u64 usec)
{
	return ktime_add_ns(kt, usec * 1000);
}

static __forceinline ktime_t ktime_sub_us(const ktime_t kt, const u64 usec)
{
	return ktime_sub_ns(kt, usec * 1000);
}

static __forceinline ktime_t ns_to_ktime(u64 ns)
{
	static const ktime_t ktime_zero = { .tv64 = 0 };
	return ktime_add_ns(ktime_zero, ns);
}

static __forceinline ktime_t ktime_get(void)
{
	s64 nsecs = 0;
	LARGE_INTEGER time;
	KeQuerySystemTime(&time);
	nsecs = time.QuadPart;
	nsecs *= 100;
	
	return (ktime_t){.tv64 = nsecs};
}
typedef size_t clockid_t;
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9

enum hrtimer_mode 
{
	HRTIMER_MODE_ABS = 0x0,		/* Time value is absolute */
	HRTIMER_MODE_REL = 0x1,		/* Time value is relative to now */
	HRTIMER_MODE_PINNED = 0x02,	/* Timer is bound to CPU */
	HRTIMER_MODE_ABS_PINNED = 0x02,
	HRTIMER_MODE_REL_PINNED = 0x03,
};

enum hrtimer_restart 
{
	HRTIMER_NORESTART,	/* Timer is not restarted */
	HRTIMER_RESTART,	/* Timer must be restarted */
};

struct timerqueue_node 
{
	ktime_t expires;
};

struct hrtimer_clock_base 
{
	int			index;
	ktime_t			resolution;
	ktime_t			(*get_time)(void);
	ktime_t			softirq_time;
	ktime_t			offset;
};

struct hrtimer 
{
	struct timerqueue_node		node;
	ktime_t				_softexpires;
	enum hrtimer_restart		(*function)(struct hrtimer *);
	struct hrtimer_clock_base	*base;
	size_t			state;
	KTIMER                  ktimer;
	KDPC                    kdpc;
	LARGE_INTEGER           due_time;
	struct hrtimer_clock_base	base_hack;
};

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id, enum hrtimer_mode mode);
int hrtimer_start(struct hrtimer *timer, ktime_t tim, const enum hrtimer_mode mode);
int hrtimer_cancel(struct hrtimer *timer);
int hrtimer_restart(struct hrtimer* timer);

static __forceinline void hrtimer_add_expires_ns(struct hrtimer *timer, u64 delta)
{
	timer->node.expires = ktime_add_ns(timer->node.expires, delta);
}

static __forceinline ktime_t hrtimer_get_expires(struct hrtimer *timer)
{
	return timer->node.expires;
}

static __forceinline u64 hrtimer_get_expires_ns(struct hrtimer *timer)
{
	return ktime_to_ns(timer->node.expires);
}

static __forceinline void hrtimer_start_expires(struct hrtimer *timer, int mode)
{
	hrtimer_start(timer, timer->node.expires, mode);
}

static __forceinline ktime_t hrtimer_expires_remaining(const struct hrtimer *timer)
{
    return ktime_sub(timer->node.expires, timer->base->get_time());
}

static __forceinline ktime_t hrtimer_get_remaining(const struct hrtimer *timer)
{
	ktime_t rem;
	rem = hrtimer_expires_remaining(timer);
	return rem;
}

/*
 Memory Management Stuffs
 */

#define BIT(nr) ((size_t)(1) << (nr))
#define GFP_KERNEL   BIT(0)
#define GFP_ATOMIC   BIT(1)
#define __GFP_ZERO   BIT(3)
#define GFP_UNALLOC  BIT(5)

 /*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef size_t		   gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;
typedef u64            phys_addr_t;

typedef size_t		   hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

typedef hfn_t pfn_t;

typedef struct page
{
	void* hva;
	void* kmap_hva;
	size_t __private;
	hpa_t hpa;
	pfn_t pfn;
	size_t gfp_mask;
	PEPROCESS proc;
}page;

extern u64 max_pagen;
extern struct page** pglist;
DECLARE_RAW_SPINLOCK(global_page_lock);

#define page_private(page)			((page)->__private)
#define set_page_private(page, v)	((page)->__private = (v))

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr), 0)

#define clear_page(page)	memset((page), 0, PAGE_SIZE)

#define virt_to_page(kaddr)	pfn_to_page((__pa(kaddr) >> PAGE_SHIFT))


static __inline void *kmalloc(size_t size, size_t flags)
{
	void* ret = NULL;
	int zero = 0;

	if (flags & __GFP_ZERO)
		zero = 1;

	ret = ExAllocatePoolWithTag(NonPagedPool, size, GVM_POOL_TAG);

	if(ret && zero)
	{
		memset(ret, 0, size);
	}
	return ret;
}

static __inline void *kzalloc(size_t size, size_t flags)
{
	return kmalloc(size, flags | __GFP_ZERO);
}

static __inline void kfree(void* hva)
{
	if (!hva)
		return;
	ExFreePoolWithTag(hva, GVM_POOL_TAG);
}

static __inline void *vmalloc(size_t size)
{
	return ExAllocatePoolWithTag(NonPagedPool, size, GVM_POOL_TAG);
}

static __inline void vfree(void* hva)
{
	if (!hva)
		return;
	ExFreePoolWithTag(hva, GVM_POOL_TAG);
}

static __inline void *vzalloc(size_t size)
{
	void *addr = vmalloc(size);
	if (addr)
	{
		memset(addr, 0, size);
	}
	return addr;
}

static __inline void *kmalloc_fast(size_t size, size_t flags)
{
	return kmalloc(size, flags);
}

static __inline void *kzalloc_fast(size_t size, size_t flags)
{
	return kmalloc_fast(size, flags | __GFP_ZERO);
}

static __inline void kfree_fast(void* hva)
{
	if (!hva)
		return;
	ExFreePoolWithTag(hva, GVM_POOL_TAG);
}

#define kvfree kfree_fast

#define VERIFY_READ		0
#define VERIFY_WRITE	1

static __inline pfn_t page_to_pfn(struct page* page)
{
	return page->pfn;
}

static __inline void* page_to_hva(struct page* page)
{
	return page->hva;
}

static __inline hpa_t page_to_phys(struct page* page)
{
	return page->hpa;
}

static __inline hpa_t mdl_to_phys(PMDL mdl)
{
	return (hpa_t)MmGetPhysicalAddress(mdl->StartVa).QuadPart;
}

static __inline struct page* pfn_to_page(pfn_t pfn)
{
	return pglist[pfn];
}

static __inline hpa_t __pa(void* va)
{
	PHYSICAL_ADDRESS addr_phys;
	addr_phys = MmGetPhysicalAddress(va);
	return (hpa_t)(addr_phys.QuadPart);
}

static __inline void* __va(hpa_t pa)
{
	void* ret = 0;
	ret = page_to_hva(pfn_to_page(pa >> PAGE_SHIFT));
	if(!ret)
	{
		printk("vmmr0: __va: invalid hpa %p\n", pa);
	}
	return ret;
}

static __inline struct page *alloc_page(unsigned int gfp_mask)
{
	void* page_hva = NULL;
	PHYSICAL_ADDRESS pageaddr_phys;
	int zero = 0;
	struct page* page = ExAllocatePoolWithTag(NonPagedPool,
						  sizeof(*page),
						  GVM_POOL_TAG);
	if(!page)
		goto out_error;

	page_hva = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, GVM_POOL_TAG);
	if(!page_hva)
		goto out_error_free;

	if (gfp_mask & __GFP_ZERO)
		zero = 0;

	ASSERT(!((size_t)page_hva & 0xfffull));

	if(zero)
		memset(page_hva, 0, PAGE_SIZE);

	pageaddr_phys = MmGetPhysicalAddress(page_hva);
	page->hpa = pageaddr_phys.QuadPart;
	page->pfn = page->hpa >> PAGE_SHIFT;
	page->hva = page_hva;
	page->gfp_mask = gfp_mask;
	page->proc = IoGetCurrentProcess();
	raw_spin_lock(&global_page_lock);
	pglist[page->pfn] = page;
	raw_spin_unlock(&global_page_lock);
	return page;

 out_error_free:
	ExFreePoolWithTag(page, GVM_POOL_TAG);
 out_error:
	return 0;
}

static __inline void __free_pages(struct page* page, unsigned int order)
{
	ExFreePoolWithTag(page->hva, GVM_POOL_TAG);

	raw_spin_lock(&global_page_lock);
	pglist[page->pfn] = 0;
	raw_spin_unlock(&global_page_lock);

	ExFreePoolWithTag(page, GVM_POOL_TAG);
}

static __inline void free_pages(size_t addr, unsigned int order)
{
	if (addr != 0)
	{
		__free_pages(virt_to_page((void *)addr), order);
	}
}

static __inline void* kmap(PMDL mdl)
{

	if (!mdl)
		return NULL;

	return MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
}

static __inline void kunmap(PMDL mdl)
{
}

static __inline void* page_address(struct page* page)
{
	BUG_ON(!page->hva);
	return page->hva;
}

static __inline void* get_zeroed_page(unsigned int gfp_mask)
{
	struct page* page = alloc_page(gfp_mask);
	memset(page->hva, 0, PAGE_SIZE);
	return page->hva;
}

static __inline size_t __get_free_page(unsigned int gfp_mask)
{
	struct page *page;
	page = alloc_page(gfp_mask);
	if (!page)
		return 0;
	return (size_t) page_address(page);
}

static __inline int get_user_pages_fast(size_t start, int nr_pages, int write,
			PMDL *mdl)
{
	PMDL _mdl;

	start &= PAGE_MASK;
	_mdl = IoAllocateMdl((void *)start, nr_pages * PAGE_SIZE,
			FALSE, FALSE, NULL);
	if (!_mdl)
		return 0;

	MmProbeAndLockPages(_mdl, KernelMode, IoWriteAccess);
	*mdl = _mdl;

	return nr_pages;
}

static __inline void kvm_release_page(PMDL mdl)
{
	if (!mdl)
		return;

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
}

/* We actually did not copy from *user* here. This function in kvm is used to
 * ioctl parameters. On Windows, we always use buffered io for device control.
 * Thus the address supplied to copy_from_user is address in kernel space.
 * Simple keep the function name here.
 * __copy_from/to_user is really copying from user space.
 */
static __inline size_t copy_from_user(void *dst, const void *src, size_t size)
{
	memcpy(dst, src, size);
	return 0;
}

static __inline size_t __copy_user(void *dst, const void *src, size_t size,
	       int from)
{
	PMDL lock_mdl;
	HANDLE handle;
	int clac = 0;

	lock_mdl = IoAllocateMdl(from? src : dst, size, FALSE, FALSE, NULL);
	if (!lock_mdl)
		return size;
	MmProbeAndLockPages(lock_mdl, UserMode, IoWriteAccess);
	handle = MmSecureVirtualMemory(from? src : dst, size, PAGE_READWRITE);
	if (!handle)
		return size;
	/*
	 * If Windows turns on SMAP, we need set AC flag before accessing
	 * user addr. However, since we do not know Windows's logic for AC
	 * flag, we only turned it on the CPU this piece of code is running
	 * and make sure we are not interrupted in the middle (in case Windows
	 * has the chance to change the AC flag).
	 */
	if (boot_cpu_has(X86_FEATURE_SMAP)) {
		local_irq_disable();
		if (__readcr4() & X86_CR4_SMAP &&
		    !(__readeflags() & X86_EFLAGS_AC)) {
			clac = 1;
			_stac();
		} else
			local_irq_enable();
	}
	memcpy(dst, src, size);
	if (clac) {
		_clac();
		local_irq_enable();
	}
	MmUnsecureVirtualMemory(handle);
	MmUnlockPages(lock_mdl);
	IoFreeMdl(lock_mdl);
	return 0;
}

static __inline size_t __copy_to_user(void *dst, const void *src, size_t size)
{
	return __copy_user(dst, src, size, 0);
}

static __inline size_t __copy_from_user(void *dst, const void *src, size_t size)
{
	return __copy_user(dst, src, size, 1);
}

static __inline void *kmap_atomic(PMDL mdl)
{
	return kmap(mdl);
}

static __inline void kunmap_atomic(PMDL mdl)
{
	kunmap(mdl);
}

static __inline void *memdup_user(const void *user, size_t size)
{
	void *buf = kzalloc(size, GFP_KERNEL);

	if (!buf)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(buf, user, size))
		return ERR_PTR(-EFAULT);
	return buf;
}

/*
 TSC
 */
static __forceinline u64 rdtsc(void)
{
	return __rdtsc();
}

static __forceinline int check_tsc_unstable(void)
{
	return 0;
}

static __forceinline int mark_tsc_unstable(void)
{
	return 0;
}


/*
 File
 */
struct file {
	void *private_data;
};

/*
Atomic Operations
*/
typedef long atomic_t;
#define ATOMIC_INIT(n) (n)
static __forceinline void atomic_inc(atomic_t *v)
{
	InterlockedIncrement(v);
}

static __forceinline void atomic_dec(atomic_t *v)
{
	InterlockedDecrement(v);
}

static __forceinline int atomic_dec_and_test(atomic_t *v)
{
	return !InterlockedDecrement(v);
}

static __forceinline int atomic_xchg(atomic_t *v, int val)
{
	return InterlockedExchange(v, val);
}

extern u8 xchg8(u8 *a, u8 b);
extern u16 xchg16(u16 *a, u16 b);
#define xchg32(a, b) InterlockedExchange((LONG *)a, b)
#define xchg64(a, b) InterlockedExchange64((LONG64 *)a, b)
extern u8 cmpxchg8(u8 *a, u8 b, u8 c);
extern u16 cmpxchg16(u16 *a, u16 b, u16 c);
#define cmpxchg32(a, b, c) InterlockedCompareExchange((LONG *)a, c, b)
#define cmpxchg64(a, b, c) InterlockedCompareExchange64((LONG64 *)a, c, b)

#define xchg(a, b) ((sizeof(*a) == 8)? xchg64((u64 *)a, b) :  \
					  ((sizeof(*a) == 4)? xchg32((u32 *)a, b) :  \
					  ((sizeof(*a) == 2)? xchg16((u16 *)a, b) :  \
					  ((sizeof(*a) == 1)? xchg8((u8 *)a, b) : 0))))
#define cmpxchg(a, b, c) ((sizeof(*a) == 8)? cmpxchg64((u64 *)a, b, c) :  \
							((sizeof(*a) == 4)? cmpxchg32((u32 *)a, b, c) :  \
							((sizeof(*a) == 2)? cmpxchg16((u16 *)a, b, c) :  \
							((sizeof(*a) == 1)? cmpxchg8((u8 *)a, b, c) : 0))))

#define atomic_cmpxchg(a, b, c) cmpxchg(a, b, c)

static __forceinline int atomic_dec_if_positive(atomic_t *v)
{
	int c, old, dec;
	c = atomic_read(v);

	for (;;) {
		dec = c - 1;
		if (unlikely(dec < 0))
			break;
		old = atomic_cmpxchg((v), c, dec);
		if (likely(old == c))
			break;
		c = old;
	}
	return dec;
}

#define smp_store_mb(var, value)  do { (void)xchg(&var, value); } while (0)
#define smp_store_release(p, v) \
do {							\
	smp_mb();					\
	*p = v;						\
} while (0)


/*
 cpumask
 */
static __inline bool zalloc_cpumask_var(cpumask_var_t *mask, int flags)
{
	*mask = NULL;
	*mask = kmalloc(sizeof(cpumask_t), flags | __GFP_ZERO);
	return !!(*mask);
}
static __inline void free_cpumask_var(cpumask_var_t mask)
{
	kfree(mask);
}

/*
 vm_mmap/unmap
 */
#define PROT_READ       0x1             /* page can be read */
#define PROT_WRITE      0x2             /* page can be written */
#define PROT_EXEC       0x4             /* page can be executed */
#define PROT_SEM        0x8             /* page may be used for atomic ops */
#define PROT_NONE       0x0             /* page can not be accessed */
#define PROT_GROWSDOWN  0x01000000      /* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP    0x02000000      /* mprotect flag: extend change to end of growsup vma */

#define MAP_SHARED      0x01            /* Share changes */
#define MAP_PRIVATE     0x02            /* Changes are private */
#define MAP_TYPE        0x0f            /* Mask for type of mapping */
#define MAP_FIXED       0x10            /* Interpret addr exactly */
#define MAP_ANONYMOUS   0x20            /* don't use a file */
#define MAP_UNINITIALIZED 0x0           /* Don't support this flag */

typedef struct gvm_mmap_node
{
	PMDL pMDL;
	PVOID pMem;
	PVOID UserVA;
	struct list_head list;
}gvm_mmap_node;

extern struct list_head gvm_mmap_list;

extern size_t vm_mmap(struct file *file, size_t addr,
	size_t len, size_t prot, size_t flag, size_t offset);
extern size_t __vm_mmap(struct file *file, size_t addr,
	size_t len, size_t prot, size_t flag, size_t offset, size_t keva);
extern int vm_munmap(size_t start, size_t len);
extern int __vm_munmap(size_t start, size_t len, bool freepage);

/*
 smp_call_function
 */
extern int smp_call_function_single(int cpu, void(*func)(void *info), void *info, int wait);
extern int smp_call_function_many(cpumask_var_t mask, void(*func) (void *info), void *info, int wait);
extern void smp_send_reschedule(int cpu);

/*
 * srcu tranlation to windows ERESOURCE
 */
struct srcu_struct {
	ERESOURCE eres;
};

static __inline int srcu_read_lock(struct srcu_struct *sp)
{
	ExAcquireResourceSharedLite(&sp->eres, true);
	return 0;
}

static __inline void __srcu_read_unlock(struct srcu_struct *sp)
{
	ExReleaseResourceLite(&sp->eres);
}
#define srcu_read_unlock(sp, idx) __srcu_read_unlock(sp)

static __inline void *srcu_dereference(void *p, struct srcu_struct *sp)
{
	return p;
}

static __inline void synchronize_srcu_expedited(struct srcu_struct *sp)
{
	ExAcquireResourceExclusiveLite(&sp->eres, true);
	ExReleaseResourceLite(&sp->eres);
}

#define synchronize_srcu(srcu) synchronize_srcu_expedited(srcu)

static __inline int init_srcu_struct(struct srcu_struct *sp)
{
	NTSTATUS rc = ExInitializeResourceLite(&sp->eres);
	return !NT_SUCCESS(rc);
}

static __inline int cleanup_srcu_struct(struct srcu_struct *sp)
{
	NTSTATUS rc = ExDeleteResourceLite(&sp->eres);
	return !NT_SUCCESS(rc);
}

/*
 * RCU
 */
static __inline __rcu_assign_pointer(void **p, void *v)
{
	*p = v;
	smp_mb();
}

#define __rcu
#define rcu_assign_pointer(p, v) __rcu_assign_pointer(&(void *)p, (void *)v)
#define rcu_read_lock()
#define rcu_read_unlock()

static __inline void *rcu_dereference_raw(void *p)
{
	return p;
}

#define rcu_dereference(a) rcu_dereference_raw(a)
#define hlist_first_rcu(head)   (*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)    (*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)   (*((struct hlist_node __rcu **)((node)->pprev)))

static __inline void hlist_add_head_rcu(struct hlist_node *n,
	struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	n->pprev = &h->first;
	rcu_assign_pointer(hlist_first_rcu(h), n);
	if (first)
		first->pprev = &n->next;
}

static __inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	n->pprev = LIST_POISON2;
}

#define hlist_for_each_entry_rcu(pos, head, member)         \
    for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
            typeof(*(pos)), member);            \
        pos;                            \
        pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
            &(pos)->member)), typeof(*(pos)), member))

/*
 * It is said there is no cpu online/offline for Windows,
 * so always return true.
 */
static bool cpu_online(int cpu)
{
	return true;
}

/*
 * xsave related functions
 */
#define XSTATE_CPUID			0x0000000d
#define XCR_XFEATURE_ENABLED_MASK	0x00000000

static inline u64 xgetbv(u32 index)
{
	return _xgetbv(index);
}

static inline void xsetbv(u32 index, u64 value)
{
	_xsetbv(index, value);
}

/*
 * host cpu vendor
 */
extern char CPUString[13];

static __inline bool is_Intel()
{
	return !strcmp("GenuineIntel", CPUString);
}

static __inline bool is_AMD()
{
	return !strcmp("AuthenticAMD", CPUString);
}

extern NTSTATUS NtKrUtilsInit(void);
extern void NtKrUtilsExit(void);
