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
#pragma warning(disable : 4018)
#pragma warning(disable : 4100)
#pragma warning(disable : 4152)
#pragma warning(disable : 4389)
#pragma warning(disable : 4267)
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#pragma warning(disable : 4245)
#include <intrin.h>
#include <ntddk.h>

#define __align(a) __declspec(align(a))
#define inline __inline
#define __always_inline __forceinline
#define __alwaysinline __forceinline

typedef unsigned char uint8_t;
typedef char int8_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef short s16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;

typedef unsigned char __u8;
typedef char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

/* This is a hack. We should really replace ulong to size_t */
typedef size_t ulong;

#define bool _Bool 
#define null NULL

/* It seems VS has size_t but not ssize_t*/
typedef intptr_t ssize_t;

// per-cpu implementation
#define MAX_CPU_NUMBERS 512 
#define DEFINE_PER_CPU(type, name) \
	type name[MAX_CPU_NUMBERS]

#define DECLARE_PER_CPU(type, name) \
	extern type name[MAX_CPU_NUMBERS]

#define per_cpu(name, cpu) \
	name[cpu]
#define this_cpu_ptr(pname)	\
    pname[raw_smp_processor_id()]
#define __this_cpu_write(name, val) \
	name[smp_processor_id()] = val

//intel pmc stuff
#define INTEL_PMC_MAX_GENERIC 32
#define INTEL_PMC_MAX_FIXED 3

struct irq_work {
	int DONOTCARE2;
};

typedef u8 mtrr_type;

#define PAGE_MASK (~(unsigned long long)(PAGE_SIZE - 1))

#define kvm_PAGE_TRACK_MAX 1

/*
* These are used to make use of C type-checking..
*/
typedef size_t   pteval_t;
typedef size_t   pmdval_t;
typedef size_t   pudval_t;
typedef size_t   pgdval_t;
typedef size_t   pgprotval_t;

typedef struct { pteval_t pte; } pte_t;

#define __default_cpu_present_to_apicid(a) 0

#define NR_CPU_REGS 17

/* BITS_PER_LONG is coming from linux kernel where long int has 64bits for
 * x86_64 and 32bits for x86. Microsoft VC always treats long as int. So
 * We keep the linux kernel definitions here. Since we replaced long(ulong)
 * to ssize_t(size_t). This definition is indeed BITS_PER_SIZET.
 */
#ifdef _WIN64
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif

#define atomic_read(a) *a

#define __must_check

#define false (unsigned char)0
#define true (unsigned char)1

#pragma warning(disable : 4201)
#pragma pack(push, 1)
struct desc_struct {
	union {
		struct {
			unsigned int a;
			unsigned int b;
		};
		struct {
			u16 limit0;
			u16 base0;
			unsigned base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
			unsigned limit : 4, avl : 1, l : 1, d : 1, g : 1, base2 : 8;
		};
	};
};

/* LDT or TSS descriptor in the GDT. 16 bytes. */
struct ldttss_desc64 { 
        u16 limit0;
        u16 base0;
        unsigned base1 : 8, type : 5, dpl : 2, p : 1;
        unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
        u32 base3;
        u32 zero1;
};
#pragma pack(pop)

static __inline size_t get_desc_base(const struct desc_struct *desc)
{
	return (size_t)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static __inline void set_desc_base(struct desc_struct *desc, size_t base)
{
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (base >> 24) & 0xff;
}

static __inline size_t get_desc_limit(const struct desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static __inline void set_desc_limit(struct desc_struct *desc, size_t limit)
{
	desc->limit0 = limit & 0xffff;
	desc->limit = (limit >> 16) & 0xf;
}

#define __user

#ifndef EPERM
#define EPERM 1 /* Operation not permitted */
#endif

#ifndef ENOENT
#define ENOENT 2 /* No such file or directory */
#endif

#ifndef ESRCH
#define ESRCH 3 /* No such process */
#endif

#ifndef EINTR
#define EINTR 4 /* Interrupted system call */
#endif

#ifndef EIO
#define EIO 5 /* I/O error */
#endif

#ifndef ENXIO
#define ENXIO 6 /* No such device or address */
#endif

#ifndef E2BIG
#define E2BIG 7 /* Arg list too long */
#endif

#ifndef ENOEXEC
#define ENOEXEC 8 /* Exec format error */
#endif

#ifndef EBADF
#define EBADF 9 /* Bad file number */
#endif

#ifndef ECHILD
#define ECHILD 10 /* No child processes */
#endif

#ifndef EAGAIN
#define EAGAIN 11 /* Try again */
#endif

#ifndef ENOMEM
#define ENOMEM 12 /* Out of memory */
#endif

#ifndef EACCES
#define EACCES 13 /* Permission denied */
#endif

#ifndef EFAULT
#define EFAULT 14 /* Bad address */
#endif

#ifndef ENOTBLK
#define ENOTBLK 15 /* Block device required */
#endif

#ifndef EBUSY
#define EBUSY 16 /* Device or resource busy */
#endif

#ifndef EEXIST
#define EEXIST 17 /* File exists */
#endif

#ifndef EXDEV
#define EXDEV 18 /* Cross-device link */
#endif

#ifndef ENODEV
#define ENODEV 19 /* No such device */
#endif

#ifndef ENOTDIR
#define ENOTDIR 20 /* Not a directory */
#endif

#ifndef EISDIR
#define EISDIR 21 /* Is a directory */
#endif

#ifndef EINVAL
#define EINVAL 22 /* Invalid argument */
#endif

#ifndef ENFILE
#define ENFILE 23 /* File table overflow */
#endif

#ifndef EMFILE
#define EMFILE 24 /* Too many open files */
#endif

#ifndef ENOTTY
#define ENOTTY 25 /* Not a typewriter */
#endif

#ifndef ETXTBSY
#define ETXTBSY 26 /* Text file busy */
#endif

#ifndef EFBIG
#define EFBIG 27 /* File too large */
#endif

#ifndef ENOSPC
#define ENOSPC 28 /* No space left on device */
#endif

#ifndef ESPIPE
#define ESPIPE 29 /* Illegal seek */
#endif

#ifndef EROFS
#define EROFS 30 /* Read-only file system */
#endif

#ifndef EMLINK
#define EMLINK 31 /* Too many links */
#endif

#ifndef EPIPE
#define EPIPE 32 /* Broken pipe */
#endif

#ifndef EDOM
#define EDOM 33 /* Math argument out of domain of func */
#endif

#ifndef ERANGE
#define ERANGE 34 /* Math result not representable */
#endif

#ifndef EDEADLK
#define EDEADLK 35 /* Resource deadlock would occur */
#endif

#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36 /* File name too long */
#endif

#ifndef ENOLCK
#define ENOLCK 37 /* No record locks available */
#endif

#ifndef ENOSYS
#define ENOSYS 38 /* Function not implemented */
#endif

#ifndef ENOTEMPTY
#define ENOTEMPTY 39 /* Directory not empty */
#endif

#ifndef ELOOP
#define ELOOP 40 /* Too many symbolic links encountered */
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN /* Operation would block */
#endif

#ifndef ENOMSG
#define ENOMSG 42 /* No message of desired type */
#endif

#ifndef EIDRM
#define EIDRM 43 /* Identifier removed */
#endif

#ifndef ECHRNG
#define ECHRNG 44 /* Channel number out of range */
#endif

#ifndef EL2NSYNC
#define EL2NSYNC 45 /* Level 2 not synchronized */
#endif

#ifndef EL3HLT
#define EL3HLT 46 /* Level 3 halted */
#endif

#ifndef EL3RST
#define EL3RST 47 /* Level 3 reset */
#endif

#ifndef ELNRNG
#define ELNRNG 48 /* Link number out of range */
#endif

#ifndef EUNATCH
#define EUNATCH 49 /* Protocol driver not attached */
#endif

#ifndef ENOCSI
#define ENOCSI 50 /* No CSI structure available */
#endif

#ifndef EL2HLT
#define EL2HLT 51 /* Level 2 halted */
#endif

#ifndef EBADE
#define EBADE 52 /* Invalid exchange */
#endif

#ifndef EBADR
#define EBADR 53 /* Invalid request descriptor */
#endif

#ifndef EXFULL
#define EXFULL 54 /* Exchange full */
#endif

#ifndef ENOANO
#define ENOANO 55 /* No anode */
#endif

#ifndef EBADRQC
#define EBADRQC 56 /* Invalid request code */
#endif

#ifndef EBADSLT
#define EBADSLT 57 /* Invalid slot */
#endif

#ifndef EDEADLOCK
#define EDEADLOCK EDEADLK
#endif

#ifndef EBFONT
#define EBFONT 59 /* Bad font file format */
#endif

#ifndef ENOSTR
#define ENOSTR 60 /* Device not a stream */
#endif

#ifndef ENODATA
#define ENODATA 61 /* No data available */
#endif

#ifndef ETIME
#define ETIME 62 /* Timer expired */
#endif

#ifndef ENOSR
#define ENOSR 63 /* Out of streams resources */
#endif

#ifndef ENONET
#define ENONET 64 /* Machine is not on the network */
#endif

#ifndef ENOPKG
#define ENOPKG 65 /* Package not installed */
#endif

#ifndef EREMOTE
#define EREMOTE 66 /* Object is remote */
#endif

#ifndef ENOLINK
#define ENOLINK 67 /* Link has been severed */
#endif

#ifndef EADV
#define EADV 68 /* Advertise error */
#endif

#ifndef ESRMNT
#define ESRMNT 69 /* Srmount error */
#endif

#ifndef ECOMM
#define ECOMM 70 /* Communication error on send */
#endif

#ifndef EPROTO
#define EPROTO 71 /* Protocol error */
#endif

#ifndef EMULTIHOP
#define EMULTIHOP 72 /* Multihop attempted */
#endif

#ifndef EDOTDOT
#define EDOTDOT 73 /* RFS specific error */
#endif

#ifndef EBADMSG
#define EBADMSG 74 /* Not a data message */
#endif

#ifndef EOVERFLOW
#define EOVERFLOW 75 /* Value too large for defined data type */
#endif

#ifndef ENOTUNIQ
#define ENOTUNIQ 76 /* Name not unique on network */
#endif

#ifndef EBADFD
#define EBADFD 77 /* File descriptor in bad state */
#endif

#ifndef EREMCHG
#define EREMCHG 78 /* Remote address changed */
#endif

#ifndef ELIBACC
#define ELIBACC 79 /* Can not access a needed shared library */
#endif

#ifndef ELIBBAD
#define ELIBBAD 80 /* Accessing a corrupted shared library */
#endif

#ifndef ELIBSCN
#define ELIBSCN 81 /* .lib section in a.out corrupted */
#endif

#ifndef ELIBMAX
#define ELIBMAX 82 /* Attempting to link in too many shared libraries */
#endif

#ifndef ELIBEXEC
#define ELIBEXEC 83 /* Cannot exec a shared library directly */
#endif

#ifndef EILSEQ
#define EILSEQ 84 /* Illegal byte sequence */
#endif

#ifndef ERESTART
#define ERESTART 85 /* Interrupted system call should be restarted */
#endif

#ifndef ESTRPIPE
#define ESTRPIPE 86 /* Streams pipe error */
#endif

#ifndef EUSERS
#define EUSERS 87 /* Too many users */
#endif

#ifndef ENOTSOCK
#define ENOTSOCK 88 /* Socket operation on non-socket */
#endif

#ifndef EDESTADDRREQ
#define EDESTADDRREQ 89 /* Destination address required */
#endif

#ifndef EMSGSIZE
#define EMSGSIZE 90 /* Message too long */
#endif

#ifndef EPROTOTYPE
#define EPROTOTYPE 91 /* Protocol wrong type for socket */
#endif

#ifndef ENOPROTOOPT
#define ENOPROTOOPT 92 /* Protocol not available */
#endif

#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 93 /* Protocol not supported */
#endif

#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT 94 /* Socket type not supported */
#endif

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95 /* Operation not supported on transport endpoint */
#endif

#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT 96 /* Protocol family not supported */
#endif

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 97 /* Address family not supported by protocol */
#endif

#ifndef EADDRINUSE
#define EADDRINUSE 98 /* Address already in use */
#endif

#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 99 /* Cannot assign requested address */
#endif

#ifndef ENETDOWN
#define ENETDOWN 100 /* Network is down */
#endif

#ifndef ENETUNREACH
#define ENETUNREACH 101 /* Network is unreachable */
#endif

#ifndef ENETRESET
#define ENETRESET 102 /* Network dropped connection because of reset */
#endif

#ifndef ECONNABORTED
#define ECONNABORTED 103 /* Software caused connection abort */
#endif

#ifndef ECONNRESET
#define ECONNRESET 104 /* Connection reset by peer */
#endif

#ifndef ENOBUFS
#define ENOBUFS 105 /* No buffer space available */
#endif

#ifndef EISCONN
#define EISCONN 106 /* Transport endpoint is already connected */
#endif

#ifndef ENOTCONN
#define ENOTCONN 107 /* Transport endpoint is not connected */
#endif

#ifndef ESHUTDOWN
#define ESHUTDOWN 108 /* Cannot send after transport endpoint shutdown */
#endif

#ifndef ETOOMANYREFS
#define ETOOMANYREFS 109 /* Too many references: cannot splice */
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 110 /* Connection timed out */
#endif

#ifndef ECONNREFUSED
#define ECONNREFUSED 111 /* Connection refused */
#endif

#ifndef EHOSTDOWN
#define EHOSTDOWN 112 /* Host is down */
#endif

#ifndef EHOSTUNREACH
#define EHOSTUNREACH 113 /* No route to host */
#endif

#ifndef EALREADY
#define EALREADY 114 /* Operation already in progress */
#endif

#ifndef EINPROGRESS
#define EINPROGRESS 115 /* Operation now in progress */
#endif

#ifndef ESTALE
#define ESTALE 116 /* Stale NFS file handle */
#endif

#ifndef EUCLEAN
#define EUCLEAN 117 /* Structure needs cleaning */
#endif

#ifndef ENOTNAM
#define ENOTNAM 118 /* Not a XENIX named type file */
#endif

#ifndef ENAVAIL
#define ENAVAIL 119 /* No XENIX semaphores available */
#endif

#ifndef EISNAM
#define EISNAM 120 /* Is a named type file */
#endif

#ifndef EREMOTEIO
#define EREMOTEIO 121 /* Remote I/O error */
#endif

#ifndef EDQUOT
#define EDQUOT 122 /* Quota exceeded */
#endif

#ifndef ENOMEDIUM
#define ENOMEDIUM 123 /* No medium found */
#endif

#ifndef EMEDIUMTYPE
#define EMEDIUMTYPE 124 /* Wrong medium type */
#endif

#ifndef ECANCELED
#define ECANCELED 125 /* Operation Cancelled */
#endif

#ifndef ENOKEY
#define ENOKEY 126 /* Required key not available */
#endif

#ifndef EKEYEXPIRED
#define EKEYEXPIRED 127 /* Key has expired */
#endif

#ifndef EKEYREVOKED
#define EKEYREVOKED 128 /* Key has been revoked */
#endif

#ifndef EKEYREJECTED
#define EKEYREJECTED 129 /* Key was rejected by service */
#endif

#ifndef MAX_ERRNO
#define MAX_ERRNO       4095
#endif

#define IS_ERR_VALUE(x) ((x) >= (size_t)-MAX_ERRNO)

static __inline void* ERR_PTR(ssize_t error)
{
	return (void *)error;
}

static __inline size_t PTR_ERR(const void *ptr)
{
	return (size_t)ptr;
}

static __inline size_t IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((size_t)ptr);
}

#define FOLL_NOWAIT 0
#define FOLL_HWPOISON 0
#define FOLL_WRITE 0
#define FOLL_TOUCH 0
#define FOLL_NOWAIT 0

#define VM_READ

#define down_read(a)
#define up_read(a)

#define WRITE_ONCE(a, b) \
do { \
	_ReadWriteBarrier(); \
	a = b; \
} while(0)
#define ACCESS_ONCE(a, b) \
do { \
	_ReadWriteBarrier(); \
	b = a; \
} while(0)
#define READ_ONCE(a, b) ACCESS_ONCE(a, b)

#define WARN_ON(a) 0

#define PIDTYPE_PID 0

#define NOTIFY_OK 0

#define atomic_set(a, b) WRITE_ONCE(*a, b)

#define XSAVE_HDR_SIZE 0
#define XSAVE_HDR_OFFSET 0x10
#define XFEATURE_MASK_EXTEND 0x0

#define might_sleep() 0

// visual c compiler does not support branch hint
#define likely(a) a
#define unlikely(a) a

#define kvm_pmu_refresh(a) 0
#define printk DbgPrint
#define pr_info_ratelimited DbgPrint
#define printk_ratelimited DbgPrint
#define printk_once DbgPrint
#define kdprint DbgPrint
#define pr_info DbgPrint
#define pr_warn_once DbgPrint

// cpuid.c
enum cpuid_leafs
{
	CPUID_1_EDX = 0,
	CPUID_8000_0001_EDX,
	CPUID_8086_0001_EDX,
	CPUID_LNX_1,
	CPUID_1_ECX,
	CPUID_C000_0001_EDX,
	CPUID_8000_0001_ECX,
	CPUID_LNX_2,
	CPUID_LNX_3,
	CPUID_7_0_EBX,
	CPUID_D_1_EAX,
	CPUID_F_0_EDX,
	CPUID_F_1_EDX,
	CPUID_8000_0008_EBX,
	CPUID_6_EAX,
	CPUID_8000_000A_EDX,
	CPUID_7_ECX,
	CPUID_8000_0007_EBX,
};

extern int CPU_HAS_X86_FEATURE_XSAVE;
extern int CPU_HAS_X86_FEATURE_PKU;
extern int CPU_HAS_X86_FEATURE_GBPAGES;
extern int CPU_HAS_X86_FEATURE_HLE;
extern int CPU_HAS_X86_FEATURE_RTM;
extern int CPU_HAS_X86_FEATURE_NX;
extern int CPU_HAS_X86_FEATURE_FXSR_OPT;
extern int CPU_HAS_X86_FEATURE_NPT;
extern int CPU_HAS_X86_FEATURE_AVIC;
extern int CPU_HAS_X86_FEATURE_DECODEASSISTS;
extern int CPU_HAS_X86_FEATURE_RDTSCP;
extern int CPU_HAS_X86_FEATURE_LBRV;
extern int CPU_HAS_X86_FEATURE_NRIPS;
extern int CPU_HAS_X86_FEATURE_SMEP;
extern int CPU_HAS_X86_FEATURE_SMAP;
extern int CPU_HAS_X86_FEATURE_MPX;
extern int CPU_HAS_X86_FEATURE_XSAVES;
extern int CPU_HAS_X86_FEATURE_CONSTANT_TSC;
extern int CPU_HAS_X86_BUG_AMD_TLB_MMATCH;
extern int CPU_HAS_X86_FEATURE_FLUSHBYASID;
extern int CPU_HAS_X86_FEATURE_OSVW;
extern int CPU_HAS_X86_FEATURE_SVM;

#define cpu_has(notused, feature) (CPU_HAS_##feature)
#define boot_cpu_has(feature) (CPU_HAS_##feature)
#define static_cpu_has(feature) (CPU_HAS_##feature)

#define WARN_ON_ONCE(a) 0

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define __min_t_func_type(a)                 \
static __inline a __##a##_min(a b, a c)        \
{                                            \
	return (b < c) ? b : c;                  \
}

__min_t_func_type(unsigned)
__min_t_func_type(u64)
__min_t_func_type(u32)
__min_t_func_type(int)

#define min_t(a, b, c)  __##a##_min((b), (c))

#define offset_in_page(p)       ((size_t)(p) & ~PAGE_MASK)
// Let's borrow MS's HYPERVISOR_ERR here
#define BUG() KeBugCheck(0x00020001)
#define BUG_ON(cond) do { if (cond) BUG();} while (0)
#define volatile

#define min3(a, b, c) min(min(a, b),c)

#pragma pack(push, 1)
struct desc_ptr {
	unsigned short size;
	size_t address;
};
#pragma pack(pop)

/*
 * Bottom two bits of selector give the ring
 * privilege level
 */
#define SEGMENT_RPL_MASK        0x3

/* User mode is privilege level 3: */
#define USER_RPL                0x3

/* Bit 2 is Table Indicator (TI): selects between LDT or GDT */
#define SEGMENT_TI_MASK         0x4
/* LDT segment has TI set ... */
#define SEGMENT_LDT             0x4
/* ... GDT has it cleared */
#define SEGMENT_GDT             0x0

#define GDT_ENTRY_INVALID_SEG   0

#define swab16 RtlUshortByteSwap
#define swab32 RtlUlongByteSwap
#define swab64 RtlUlonglongByteSwap

#define container_of CONTAINING_RECORD
#define KERN_WARNING
#define KERN_INFO
#define KERN_ERR
#define KERN_CRIT
#define KERN_DEBUG

// Bitmaps 
#define BITS_TO_LONGS(bits) (bits + BITS_PER_LONG - 1)/BITS_PER_LONG
#define DECLARE_BITMAP(name, bits) \
	size_t name[BITS_TO_LONGS(bits)]

#define BITMAP_FIRST_WORD_MASK(start) (~(size_t)0 << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~(size_t)0 >> (-((ssize_t)nbits) & (BITS_PER_LONG - 1)))

#define small_const_nbits(nbits) \
        ((nbits) <= BITS_PER_LONG)

static __inline int __bitmap_and(size_t *dst, const size_t *bitmap1,
	const size_t *bitmap2, unsigned int bits)
{
	unsigned int k;
	unsigned int lim = bits / BITS_PER_LONG;
	size_t result = 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = bitmap1[k] & bitmap2[k]);
	if (bits % BITS_PER_LONG)
		result |= (dst[k] = bitmap1[k] & bitmap2[k] &
			BITMAP_LAST_WORD_MASK(bits));
	return result != 0;
}

static __inline void __bitmap_or(size_t *dst, const size_t *bitmap1,
	const size_t *bitmap2, unsigned int bits)
{
	unsigned int k;
	unsigned int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] | bitmap2[k];
}

static __inline void __bitmap_xor(size_t *dst, const size_t *bitmap1,
	const size_t *bitmap2, unsigned int bits)
{
	unsigned int k;
	unsigned int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] ^ bitmap2[k];
}

static __inline int __bitmap_andnot(size_t *dst, const size_t *bitmap1,
	const size_t *bitmap2, unsigned int bits)
{
	unsigned int k;
	unsigned int lim = bits / BITS_PER_LONG;
	size_t result = 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k]);
	if (bits % BITS_PER_LONG)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k] &
			BITMAP_LAST_WORD_MASK(bits));
	return result != 0;
}

static __inline void __bitmap_complement(size_t *dst, const size_t *src, unsigned int bits)
{
	unsigned int k, lim = bits / BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		dst[k] = ~src[k];

	if (bits % BITS_PER_LONG)
		dst[k] = ~src[k];
}

static __inline void bitmap_zero(size_t *dst, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = 0UL;
	else {
		unsigned int len = BITS_TO_LONGS(nbits) * sizeof(size_t);
		memset(dst, 0, len);
	}
}

static __inline void bitmap_copy(size_t *dst, const size_t *src,
	unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src;
	else {
		unsigned int len = BITS_TO_LONGS(nbits) * sizeof(size_t);
		memcpy(dst, src, len);
	}
}

static __inline int bitmap_and(size_t *dst, const size_t *src1,
	const size_t *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_and(dst, src1, src2, nbits);
}

static __inline void bitmap_or(size_t *dst, const size_t *src1,
	const size_t *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src1 | *src2;
	else
		__bitmap_or(dst, src1, src2, nbits);
}

static __inline void bitmap_xor(size_t *dst, const size_t *src1,
	const size_t *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src1 ^ *src2;
	else
		__bitmap_xor(dst, src1, src2, nbits);
}

static __inline int bitmap_andnot(size_t *dst, const size_t *src1,
	const size_t *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & ~(*src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_andnot(dst, src1, src2, nbits);
}

static inline void bitmap_complement(size_t *dst, const size_t *src,
	unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = ~(*src);
	else
		__bitmap_complement(dst, src, nbits);
}

// Bitwise operations
#ifdef _WIN64
// Non-atomic
static __forceinline bool __test_and_set_bit(size_t pos, volatile size_t *bitmap)
{
	return _bittestandset64((LONG64 *)bitmap, (LONG64)pos);
}

// Non-atomic
static __forceinline bool __test_and_clear_bit(size_t pos, volatile size_t *bitmap)
{
	return _bittestandreset64((LONG64 *)bitmap, (LONG64)pos);
}

// Atomic
static __forceinline bool test_and_set_bit(size_t pos, volatile size_t *bitmap)
{
	return _interlockedbittestandset64((LONG64 *)bitmap, (LONG64)pos);
}

// Atomic
static __forceinline bool test_and_clear_bit(size_t pos, volatile size_t *bitmap)
{
	return _interlockedbittestandreset64((LONG64 *)bitmap, (LONG64)pos);
}

// Non-atomic
static __forceinline void __set_bit(size_t nr, volatile size_t *addr)
{
	_bittestandset64((LONG64 *)addr, (LONG64)nr);
}

// Non-atomic
static __forceinline void __clear_bit(size_t nr, volatile size_t *addr)
{
	_bittestandreset64((LONG64 *)addr, (LONG64)nr);
}

// Atomic
static __forceinline void set_bit(size_t nr, volatile size_t *addr)
{
	_interlockedbittestandset64((LONG64 *)addr, (LONG64)nr);
}

// Atomic
static __forceinline void clear_bit(size_t nr, volatile size_t *addr)
{
	_interlockedbittestandreset64((LONG64 *)addr, (LONG64)nr);
}

static __forceinline unsigned char test_bit(size_t nr, volatile size_t *addr)
{
	return _bittest64((LONG64 *)addr, (LONG64)nr);
}
#else
// Non-atomic
static __forceinline bool __test_and_set_bit(size_t pos, volatile size_t *bitmap)
{
	return _bittestandset((LONG *)bitmap, (LONG)pos);
}

// Non-atomic
static __forceinline bool __test_and_clear_bit(size_t pos, volatile size_t *bitmap)
{
	return _bittestandreset((LONG *)bitmap, (LONG)pos);
}

// Atomic
static __forceinline bool test_and_set_bit(size_t pos, volatile size_t *bitmap)
{
	return _interlockedbittestandset((LONG *)bitmap, (LONG)pos);
}

// Atomic
static __forceinline bool test_and_clear_bit(size_t pos, volatile size_t *bitmap)
{
	return _interlockedbittestandreset((LONG *)bitmap, (LONG)pos);
}

// Non-atomic
static __forceinline void __set_bit(size_t nr, volatile size_t *addr)
{
	_bittestandset((LONG *)addr, (LONG)nr);
}

// Non-atomic
static __forceinline void __clear_bit(size_t nr, volatile size_t *addr)
{
	_bittestandreset((LONG *)addr, (LONG)nr);
}

// Atomic
static __forceinline void set_bit(size_t nr, volatile size_t *addr)
{
	_interlockedbittestandset((LONG *)addr, (LONG)nr);
}

// Atomic
static __forceinline void clear_bit(size_t nr, volatile size_t *addr)
{
	_interlockedbittestandreset((LONG *)addr, (LONG)nr);
}

static __forceinline unsigned char test_bit(size_t nr, volatile size_t *addr)
{
	return _bittest((LONG *)addr, (LONG)nr);
}
#endif

#ifdef _WIN64
static __forceinline size_t __ffs(size_t mask)
{
	unsigned long pos;
	_BitScanForward64(&pos, mask);
	return pos;
}

static __forceinline size_t __fls(size_t mask)
{
	unsigned long pos;
	_BitScanReverse64(&pos, mask);
	return pos;
}
#else
static __forceinline size_t __ffs(size_t mask)
{
	unsigned long pos;
	_BitScanForward(&pos, mask);
	return pos;
}

static __forceinline size_t __fls(size_t mask)
{
	unsigned long pos;
	_BitScanReverse(&pos, mask);
	return pos;
}
#endif


// Note the difference of linux kernel ffs with BitScanForward
static __forceinline unsigned int ffs(int x)
{
	unsigned long pos;
	unsigned char ret = _BitScanForward(&pos, x);
	return ret ? pos + 1 : ret;
}

static __forceinline size_t ffz(size_t x)
{
	return __ffs(~x);
}

static __forceinline unsigned int fls(int x)
{
	unsigned long pos;
	unsigned char ret = _BitScanReverse(&pos, x);
	return ret ? pos + 1 : ret;
}

#ifdef _WIN64
static __forceinline int fls64(size_t x)
{
	unsigned long pos;
	unsigned char ret = _BitScanReverse64(&pos, x);
	return ret ? pos + 1 : ret;
}
#else
static __forceinline int fls64(__u64 x)
{
	__u32 h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#endif

static __forceinline u64 do_div(u64 *n, u64 base)
{
	u64 rem = (*n) % base;
	*n = (*n) / base;

	return rem;
}

#ifdef _WIN64
static __inline uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	return dividend / divisor;
}
#else
static __inline uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	uint32_t high, d;

	high = divisor >> 32;
	if (high)
	{
		unsigned int shift = __fls(high);

		d = divisor >> shift;
		dividend >>= shift;
	}
	else
	{
		d = divisor;
	}

	do_div(dividend, d);

	return dividend;
}
#endif

#define __read_mostly

#define HZ 100

#define module_param_named(a, b, c, d) 0
#define module_param(a, b, c) 0

#define GDT_ENTRY_TSS	8

#define _PAGE_BIT_PRESENT       0       /* is present */
#define _PAGE_BIT_RW            1       /* writeable */
#define _PAGE_BIT_USER          2       /* userspace addressable */
#define _PAGE_BIT_PWT           3       /* page write through */
#define _PAGE_BIT_PCD           4       /* page cache disabled */
#define _PAGE_BIT_ACCESSED      5       /* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY         6       /* was written to (raised by CPU) */
#define _PAGE_BIT_PSE           7       /* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT           7       /* on 4KB pages */
#define _PAGE_BIT_GLOBAL        8       /* Global TLB entry PPro+ */
#define _PAGE_BIT_SOFTW1        9       /* available for programmer */
#define _PAGE_BIT_SOFTW2        10      /* " */
#define _PAGE_BIT_SOFTW3        11      /* " */
#define _PAGE_BIT_PAT_LARGE     12      /* On 2MB or 1GB pages */
#define _PAGE_BIT_SOFTW4        58      /* available for programmer */
#define _PAGE_BIT_PKEY_BIT0     59      /* Protection Keys, bit 1/4 */
#define _PAGE_BIT_PKEY_BIT1     60      /* Protection Keys, bit 2/4 */
#define _PAGE_BIT_PKEY_BIT2     61      /* Protection Keys, bit 3/4 */
#define _PAGE_BIT_PKEY_BIT3     62      /* Protection Keys, bit 4/4 */
#define _PAGE_BIT_NX            63      /* No execute: only valid after cpuid check */

#define _PAGE_BIT_SPECIAL       _PAGE_BIT_SOFTW1
#define _PAGE_BIT_CPA_TEST      _PAGE_BIT_SOFTW1
#define _PAGE_BIT_HIDDEN        _PAGE_BIT_SOFTW3 /* hidden by kmemcheck */
#define _PAGE_BIT_SOFT_DIRTY    _PAGE_BIT_SOFTW3 /* software dirty tracking */
#define _PAGE_BIT_DEVMAP        _PAGE_BIT_SOFTW4

/* If _PAGE_BIT_PRESENT is clear, we use these: */
/* - if the user mapped it with PROT_NONE; pte_present gives true */
#define _PAGE_BIT_PROTNONE      _PAGE_BIT_GLOBAL

#define _AT(x, y) y

#define _PAGE_PRESENT   (_AT(pteval_t, 1) << _PAGE_BIT_PRESENT)
#define _PAGE_RW        (_AT(pteval_t, 1) << _PAGE_BIT_RW)
#define _PAGE_USER      (_AT(pteval_t, 1) << _PAGE_BIT_USER)
#define _PAGE_PWT       (_AT(pteval_t, 1) << _PAGE_BIT_PWT)
#define _PAGE_PCD       (_AT(pteval_t, 1) << _PAGE_BIT_PCD)
#define _PAGE_ACCESSED  (_AT(pteval_t, 1) << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY     (_AT(pteval_t, 1) << _PAGE_BIT_DIRTY)
#define _PAGE_PSE       (_AT(pteval_t, 1) << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL    (_AT(pteval_t, 1) << _PAGE_BIT_GLOBAL)
#define _PAGE_SOFTW1    (_AT(pteval_t, 1) << _PAGE_BIT_SOFTW1)
#define _PAGE_SOFTW2    (_AT(pteval_t, 1) << _PAGE_BIT_SOFTW2)
#define _PAGE_PAT       (_AT(pteval_t, 1) << _PAGE_BIT_PAT)
#define _PAGE_PAT_LARGE (_AT(pteval_t, 1) << _PAGE_BIT_PAT_LARGE)
#define _PAGE_SPECIAL   (_AT(pteval_t, 1) << _PAGE_BIT_SPECIAL)
#define _PAGE_CPA_TEST  (_AT(pteval_t, 1) << _PAGE_BIT_CPA_TEST)

#define NMI_VECTOR 2

#define pr_err_ratelimited DbgPrint
#define pr_err DbgPrint
#define pr_debug DbgPrint

//TODO:IOW/R
#define FILE_DEVICE_GVM 0xE3E3
#define _IO(a, b)           CTL_CODE(FILE_DEVICE_GVM,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOR(a, b, c)       CTL_CODE(FILE_DEVICE_GVM,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOW(a, b, c)       CTL_CODE(FILE_DEVICE_GVM,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOWR(a, b, c)      CTL_CODE(FILE_DEVICE_GVM,b,METHOD_BUFFERED,FILE_ANY_ACCESS)

// bit maps

/*
* This looks more complex than it should be. But we need to
* get the type for the ~ right in round_down (it needs to be
* as wide as the result!), and we want to evaluate the macro
* arguments just once each.
*/
#define __round_mask(x, y) ((size_t)((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

/*
* This is a common helper function for find_next_bit and
* find_next_zero_bit.  The difference is the "invert" argument, which
* is XORed with each fetched word before searching it for one bits.
*/

static size_t _find_next_bit(const size_t *addr,
	size_t nbits, size_t start, size_t invert)
{
	size_t tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

static size_t find_next_bit(const size_t *addr, size_t size, size_t offset)
{
	return _find_next_bit(addr, size, offset, (size_t)0);
}

static size_t find_next_zero_bit(const size_t *addr, size_t size, size_t offset)
{
	return _find_next_bit(addr, size, offset, ~(size_t)0);
}
/*
* Find the first zero bit in a memory region
*/
static size_t find_first_zero_bit(const size_t *addr, size_t size)
{
	size_t idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

/*
* Find the first set bit in a memory region.
*/
static __inline size_t find_first_bit(const size_t *addr, size_t size)
{
	size_t idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}

#define for_each_set_bit(bit, addr, size) \
        for ((bit) = find_first_bit((addr), (size)); \
             (bit) < (size); \
             (bit) = find_next_bit((addr), (size), (bit) + 1))

#define REPEAT_BYTE(x)  ((~0ull / 0xff) * (x))

//cpumask
#define NR_CPUS 512
struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); };
typedef struct cpumask cpumask_t;
typedef struct cpumask *cpumask_var_t;
#define cpumask_bits(maskp) (&((maskp)->bits[0]))

static inline unsigned int cpumask_check(unsigned int cpu)
{
	return cpu;
}

static __inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static __inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static __inline void cpumask_clear(struct cpumask *dstp)
{
	memset(dstp->bits, 0, NR_CPUS / 8);
}

static __inline unsigned char cpumask_test_cpu(int cpu, struct cpumask *dstp)
{
	return test_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline bool cpumask_empty(const struct cpumask *srcp)
{
	return find_first_bit(cpumask_bits(srcp), MAX_CPU_NUMBERS)
		== MAX_CPU_NUMBERS;
}

static _forceinline unsigned int cpumask_next(int n, const struct cpumask *srcp)
{
	return (unsigned int)_find_next_bit(cpumask_bits(srcp), MAX_CPU_NUMBERS, n+1, 0);
}

/**
* for_each_cpu - iterate over every cpu in a mask
* @cpu: the (optionally unsigned) integer iterator
* @mask: the cpumask pointer
*
* After the loop, cpu is >= nr_cpu_ids.
*/
#define for_each_cpu(cpu, mask)                         \
        for ((cpu) = -1;                                \
                (cpu) = cpumask_next((cpu), (mask)),    \
                (cpu) < MAX_CPU_NUMBERS;)

#define for_each_online_cpu(cpu) \
	for_each_cpu(cpu, cpu_online_mask)

#define for_each_possible_cpu(cpu) \
	for_each_cpu(cpu, cpu_online_mask)

#define VM_FAULT_SIGBUS 0x0002

/*
* Defines x86 CPU feature bits
*/
#define NCAPINTS        18      /* N 32-bit words worth of info */
#define NBUGINTS        1       /* N 32-bit bug flags */

/*
*  CPU type and hardware bug flags. Kept separately for each CPU.
*  Members of this structure are referenced in head.S, so think twice
*  before touching them. [mj]
*/

struct cpuinfo_x86 {
	__u8                    x86;            /* CPU family */
	__u8                    x86_vendor;     /* CPU vendor */
	__u8                    x86_model;
	__u8                    x86_mask;
#ifdef CONFIG_X86_32
	char                    wp_works_ok;    /* It doesn't on 386's */

											/* Problems on some 486Dx4's and old 386's: */
	char                    rfu;
	char                    pad0;
	char                    pad1;
#else
	/* Number of 4K pages in DTLB/ITLB combined(in pages): */
	int                     x86_tlbsize;
#endif
	__u8                    x86_virt_bits;
	__u8                    x86_phys_bits;
	/* CPUID returned core id bits: */
	__u8                    x86_coreid_bits;
	/* Max extended CPUID function supported: */
	__u32                   extended_cpuid_level;
	/* Maximum supported CPUID level, -1=no CPUID: */
	int                     cpuid_level;
	__u32                   x86_capability[NCAPINTS + NBUGINTS];
	char                    x86_vendor_id[16];
	char                    x86_model_id[64];
	/* in KB - valid for CPUS which support this call: */
	int                     x86_cache_size;
	int                     x86_cache_alignment;    /* In bytes */
													/* Cache QoS architectural values: */
	int                     x86_cache_max_rmid;     /* max index */
	int                     x86_cache_occ_scale;    /* scale to bytes */
	int                     x86_power;
	unsigned long           loops_per_jiffy;
	/* cpuid returned max cores value: */
	u16                      x86_max_cores;
	u16                     apicid;
	u16                     initial_apicid;
	u16                     x86_clflush_size;
	/* number of cores as seen by the OS: */
	u16                     booted_cores;
	/* Physical processor id: */
	u16                     phys_proc_id;
	/* Logical processor id: */
	u16                     logical_proc_id;
	/* Core id: */
	u16                     cpu_core_id;
	/* Index into per_cpu list: */
	u16                     cpu_index;
	u32                     microcode;
};

extern struct cpuinfo_x86	boot_cpu_data;

#pragma warning(disable : 4214)
/* 16byte gate */
#pragma pack(push, 1)
struct gate_struct64 {
	u16 offset_low;
	u16 segment;
	u16 ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	u16 offset_middle;
	u32 offset_high;
	u32 zero1;
};
#pragma pack(pop)
#ifdef CONFIG_X86_64
typedef struct gate_struct64 gate_desc;
#define gate_offset(g) ((g).offset_low | ((size_t)(g).offset_middle << 16) | ((size_t)(g).offset_high << 32))
#endif

