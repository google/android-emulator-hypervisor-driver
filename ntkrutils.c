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

#include <ntddk.h>
#include <aehd_types.h>
#include <ntkrutils.h>
#include <linux/list.h>

LIST_HEAD(global_malloc_list);
DEFINE_SPINLOCK(global_malloc_lock);
struct page** pglist;
DEFINE_SPINLOCK(global_page_lock);

int CPU_HAS_X86_FEATURE_XSAVE;
int CPU_HAS_X86_FEATURE_PKU;
int CPU_HAS_X86_FEATURE_GBPAGES;
int CPU_HAS_X86_FEATURE_HLE;
int CPU_HAS_X86_FEATURE_RTM;
int CPU_HAS_X86_FEATURE_NX;
int CPU_HAS_X86_FEATURE_FXSR_OPT;
int CPU_HAS_X86_FEATURE_NPT;
int CPU_HAS_X86_FEATURE_AVIC;
int CPU_HAS_X86_FEATURE_DECODEASSISTS;
int CPU_HAS_X86_FEATURE_RDTSCP;
int CPU_HAS_X86_FEATURE_LBRV;
int CPU_HAS_X86_FEATURE_NRIPS;
int CPU_HAS_X86_FEATURE_SMEP;
int CPU_HAS_X86_FEATURE_SMAP;
int CPU_HAS_X86_FEATURE_MPX;
int CPU_HAS_X86_FEATURE_XSAVES;
int CPU_HAS_X86_FEATURE_CONSTANT_TSC;
int CPU_HAS_X86_BUG_AMD_TLB_MMATCH;
int CPU_HAS_X86_FEATURE_FLUSHBYASID;
int CPU_HAS_X86_FEATURE_OSVW;
int CPU_HAS_X86_FEATURE_SVM;

struct cpumask __cpu_online_mask;
struct cpumask *cpu_online_mask = &__cpu_online_mask;
unsigned int cpu_online_count;
u64 max_pagen;
char CPUString[13];

DEFINE_PER_CPU(struct cpu_getput_cxt, cpu_getput_cxt);

typedef struct _KAFFINITY_EX {
	uint16_t Count;
	uint16_t Size;
	uint32_t Padding;
	uint64_t bitmap[20];
} KAFFINITYEX, *PKAFFINITYEX;

typedef void (NTAPI *PFNHALREQUESTIPI)(uint32_t, PKAFFINITYEX);
typedef void (NTAPI *PFNKEINITIALIZEAFFINITYEX)(PKAFFINITYEX);
typedef void (NTAPI *PFNKEADDPROCESSORAFFINITYEX)(PKAFFINITYEX, uint32_t);

PFNHALREQUESTIPI pHalRequestIpi;
PFNKEINITIALIZEAFFINITYEX pKeInitializeAffinityEx;
PFNKEADDPROCESSORAFFINITYEX pKeAddProcessorAffinityEx;

// Fix me: We assume there is not cpu online at this time

NTSTATUS aehdGetCpuOnlineMap(void)
{
	NTSTATUS rc;
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *inf = NULL;
	PPROCESSOR_GROUP_INFO pginf = NULL;
	PROCESSOR_NUMBER pn;
	ULONG buffSize = 0;
	u32 ig;
	u32 ip;
	u32 cpuIndex;

	cpu_online_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	rc = KeQueryLogicalProcessorRelationship(NULL,
			RelationGroup, NULL, &buffSize);
	NT_ASSERT(rc == STATUS_INFO_LENGTH_MISMATCH);

	inf = ExAllocatePoolWithTag(NonPagedPool, buffSize, AEHD_POOL_TAG);

	if (!inf)
		return STATUS_INSUFFICIENT_RESOURCES;

	rc = KeQueryLogicalProcessorRelationship(NULL, RelationGroup,
			inf, &buffSize);

	if (!NT_SUCCESS(rc))
		goto mapout;

	for (ig = 0; NT_SUCCESS(rc) && ig < inf->Group.ActiveGroupCount; ig++) {
		pginf = &inf->Group.GroupInfo[ig];

		for (ip = 0; ip < pginf->MaximumProcessorCount; ip++) {
			pn.Group = ig;
			pn.Number = ip;
			pn.Reserved = 0;

			cpuIndex = KeGetProcessorIndexFromNumber(&pn);

			if (cpuIndex == INVALID_PROCESSOR_INDEX) {
				DbgPrint("Cannot find CPU Index for processor \
					 in group %d[%d", ig, ip);
				continue;
			}

			if (test_bit(ip, &pginf->ActiveProcessorMask))
				cpumask_set_cpu(cpuIndex, cpu_online_mask);
			else
				DbgPrint("Processor %d inside group %d[%d] \
					 is not active", cpuIndex, ig, ip);
		}
	}

mapout:
	ExFreePoolWithTag(inf, AEHD_POOL_TAG);
	return rc;
}

/*
 Timer Stuffs
 */
void timer_callback_fn(PEX_TIMER ex_timer, PVOID ex_timer_context)
{
	struct hrtimer *timer = (struct hrtimer*)ex_timer_context;
	enum hrtimer_restart ret = timer->function(timer);
	if(ret == HRTIMER_RESTART)
		hrtimer_restart(timer);
}

int hrtimer_init(struct hrtimer *timer, clockid_t clock_id, enum hrtimer_mode mode)
{
	timer->ex_timer = ExAllocateTimer(timer_callback_fn, timer, EX_TIMER_HIGH_RESOLUTION);
	if (!timer->ex_timer)
		return 1;
	ExInitializeSetTimerParameters(&timer->ext_set_parameters);
	timer->base = &timer->base_hack;
	timer->base->get_time = ktime_get;
	return 0;
}

int hrtimer_start(struct hrtimer *timer, ktime_t tim, const enum hrtimer_mode mode)
{
	int r;
	LARGE_INTEGER time;
	LONGLONG duetime;
	// We only emulate hrtimer mode that KVM uses
	ASSERTMSG("Unsupported hrtimer mode", mode == HRTIMER_MODE_ABS_PINNED);
	timer->due_time.QuadPart = ktime_to_ns(tim);
	timer->node.expires = tim;
	do_div(&(u64)timer->due_time.QuadPart, 100);
	KeQuerySystemTime(&time);
	duetime = timer->due_time.QuadPart - time.QuadPart;
	if (duetime < 0)
		duetime = 0;
	r = (int)ExSetTimer(timer->ex_timer, -duetime, 0, &timer->ext_set_parameters);
	return r;
}

int hrtimer_cancel(struct hrtimer *timer)
{
	int r;
	r = ExCancelTimer(timer->ex_timer, NULL);
	return r;
}

int hrtimer_restart(struct hrtimer* timer)
{
	int r;
	LARGE_INTEGER time;
	LONGLONG duetime;

	timer->due_time.QuadPart = ktime_to_ns(timer->node.expires);
	do_div(&(u64)timer->due_time.QuadPart, 100);
	KeQuerySystemTime(&time);
	duetime = timer->due_time.QuadPart - time.QuadPart;
	if (duetime < 0)
		duetime = 0;
	r = (int)ExSetTimer(timer->ex_timer, -duetime, 0, &timer->ext_set_parameters);
	return r;
}

void hrtimer_delete(struct hrtimer* timer)
{
	EXT_DELETE_PARAMETERS ext_delete_parameters;

	ExInitializeDeleteTimerParameters(&ext_delete_parameters);
	ExDeleteTimer(timer->ex_timer, TRUE, FALSE, &ext_delete_parameters);
}

struct list_head aehd_mmap_list;
DEFINE_RAW_SPINLOCK(aehd_mmap_lock);

size_t vm_mmap(struct file *notused, size_t addr, size_t len, size_t prot,
	       size_t flag, size_t offset)
{
	return __vm_mmap(notused, addr, len, prot, flag, offset, 0);
}

size_t __declspec(noinline) __vm_mmap(struct file *notused, size_t addr,
	       size_t len, size_t prot, size_t flag, size_t offset, size_t keva)
{
	PMDL pMDL = NULL;
	PVOID pMem = NULL;
	PVOID UserVA = NULL;
	struct aehd_mmap_node *node;

	node = ExAllocatePoolWithTag(NonPagedPool,
				     sizeof(struct aehd_mmap_node),
				     AEHD_POOL_TAG);
	if (!node)
		return (size_t)NULL;

	if (keva)
		pMem = (PVOID)keva;
	else {
		pMem = ExAllocatePoolWithTag(NonPagedPool, len, AEHD_POOL_TAG);
		if (!pMem)
			goto free_node;
		RtlZeroMemory(pMem, len);
	}

	pMDL = IoAllocateMdl(pMem, len, FALSE, FALSE, NULL);
	if (!pMDL)
		goto free_pmem;

	MmBuildMdlForNonPagedPool(pMDL);
	UserVA = MmMapLockedPagesSpecifyCache(pMDL, UserMode, MmCached,
		       0, 0, NormalPagePriority);

	if (!UserVA)
		goto free_mdl;

	node->UserVA = UserVA;
	node->pMDL = pMDL;
	node->pMem = pMem;

	raw_spin_lock(&aehd_mmap_lock);
	list_add_tail(&node->list, &aehd_mmap_list);
	raw_spin_unlock(&aehd_mmap_lock);

	return (size_t)UserVA;

 free_mdl:
	IoFreeMdl(pMDL);
 free_pmem:
	if (keva)
		ExFreePoolWithTag(pMem, AEHD_POOL_TAG);
 free_node:
	ExFreePoolWithTag(node, AEHD_POOL_TAG);

	return (size_t)NULL;
}

int vm_munmap(size_t start, size_t len)
{
	return __vm_munmap(start, len, true);
}

int __declspec(noinline) __vm_munmap(size_t start, size_t len, bool freepage)
{
	struct aehd_mmap_node *node = NULL;
	int find = 0;

	raw_spin_lock(&aehd_mmap_lock);
#define LIST_ENTRY_TYPE_INFO struct aehd_mmap_node
	list_for_each_entry(node, &aehd_mmap_list, list)
		if (node->UserVA == (PVOID)start) {
			find = 1;
			break;
		}
#undef LIST_ENTRY_TYPE_INFO
	if (find)
		list_del(&node->list);
	raw_spin_unlock(&aehd_mmap_lock);

	if (!find)
		return -1;

	BUG_ON(!node->UserVA);
	BUG_ON(!node->pMDL);
	BUG_ON(!node->pMem);

	MmUnmapLockedPages(node->UserVA, node->pMDL);
	IoFreeMdl(node->pMDL);

	if (freepage)
		ExFreePoolWithTag(node->pMem, AEHD_POOL_TAG);

	ExFreePoolWithTag(node, AEHD_POOL_TAG);
	return 0;
}

struct sfc_data {
	void (*func)(void *info);
	void *info;
	int done;
	struct spin_lock lock;
};

DEFINE_PER_CPU(KDPC, ipi_dpc);
DEFINE_PER_CPU(struct sfc_data, smp_call_function_data);

static void sfc_dpc_routine(KDPC *Dpc, PVOID DeferredContext,
		PVOID func, PVOID info)
{
	struct sfc_data *sfc_data;
	sfc_data = &per_cpu(smp_processor_id(), smp_call_function_data);
	if (sfc_data->func)
		sfc_data->func(sfc_data->info);
	sfc_data->done = 1;
}

/*
 * smp_call_function_xxx has been changed several times from KeIpiGenericCall
 * to HalRequestIpi...
 * Current version used DPC with HighImportance to emulate physical IPIs.
 * The major concern here is making code easy to debug. Playing with physical
 * IPIs incorrectly (some time even correctly) can hang the system and WinDbg
 * cannot debug these cases.
 * We may later to switch to physical IPIs.
 * Note: a DPC (or an IPI) issued to current processor just preempts the
 * code.
 */
int smp_call_function_many(cpumask_var_t mask,
	void(*func) (void *info), void *info, int wait)
{
	int cpu;
	struct sfc_data *sfc_data;

	for_each_cpu(cpu, mask) {
		sfc_data = &per_cpu(cpu, smp_call_function_data);
		spin_lock(&sfc_data->lock);
		sfc_data->func = func;
		sfc_data->info = info;
		sfc_data->done = 0;
		if (!KeInsertQueueDpc(&per_cpu(cpu, ipi_dpc),
						NULL, NULL))
			DbgBreakPoint();
	}

	for_each_cpu(cpu, mask) {
		sfc_data = &per_cpu(cpu, smp_call_function_data);
		while (!sfc_data->done)
			_mm_pause();
		spin_unlock(&sfc_data->lock);
	}

	return 0;
}

int smp_call_function_single(int cpu, void(*func)(void *info),
	void *info, int wait)
{
	struct sfc_data *sfc_data;

	sfc_data = &per_cpu(cpu, smp_call_function_data);
	spin_lock(&sfc_data->lock);
	sfc_data->func = func;
	sfc_data->info = info;
	sfc_data->done = 0;
	if (!KeInsertQueueDpc(&per_cpu(cpu, ipi_dpc),
				       	func, info))
		DbgBreakPoint();
	while (!sfc_data->done)
		_mm_pause();
	spin_unlock(&sfc_data->lock);
	return 0;
}

static_assert(sizeof(KAFFINITYEX) <= 0x200, "KAFFINITYEX is bigger than 0x200");
void smp_send_reschedule(int cpu)
{
	// This is to workaround the size change of KAFFINITY
	// between Windows 10 releases
	char __kaff[0x200];
	PKAFFINITYEX target = (PKAFFINITYEX)&__kaff[0];

	pKeInitializeAffinityEx(target);
	pKeAddProcessorAffinityEx(target, cpu);
	pHalRequestIpi(0, target);
}

enum cpuid_reg {
	CPUID_EAX = 0,
	CPUID_EBX,
	CPUID_ECX,
	CPUID_EDX,
};

#define check_cpu_has(name, leaf, reg, bitpos)                \
	do {                                                      \
		__cpuid(cpuid_info, leaf);                          \
		CPU_HAS_##name = !!(cpuid_info[reg] & (1 << bitpos)); \
	} while (0)

#define check_cpu_has_ex(name, leaf, level, reg, bitpos)      \
	do {                                                      \
		__cpuidex(cpuid_info, leaf, level);                   \
		CPU_HAS_##name = !!(cpuid_info[reg] & (1 << bitpos)); \
	} while (0)

		
static void cpu_features_init(void)
{
	int cpuid_info[4] = { 0 };

	check_cpu_has(X86_FEATURE_XSAVE, 1, CPUID_ECX, 26);

	check_cpu_has(X86_FEATURE_OSVW, 0x80000001, CPUID_ECX, 9);
	check_cpu_has(X86_FEATURE_SVM, 0x80000001, CPUID_ECX, 2);

	check_cpu_has(X86_FEATURE_NX, 0x80000001, CPUID_EDX, 20);
	check_cpu_has(X86_FEATURE_FXSR_OPT, 0x80000001, CPUID_EDX, 25);
	check_cpu_has(X86_FEATURE_GBPAGES, 0x80000001, CPUID_EDX, 26);
	check_cpu_has(X86_FEATURE_RDTSCP, 0x80000001, CPUID_EDX, 27);

	check_cpu_has_ex(X86_FEATURE_HLE, 7, 0, CPUID_EBX, 4);
	check_cpu_has_ex(X86_FEATURE_SMEP, 7, 0, CPUID_EBX, 7);
	check_cpu_has_ex(X86_FEATURE_RTM, 7, 0, CPUID_EBX, 11);
	check_cpu_has_ex(X86_FEATURE_MPX, 7, 0, CPUID_EBX, 14);
	check_cpu_has_ex(X86_FEATURE_SMAP, 7, 0, CPUID_EBX, 20);

	check_cpu_has_ex(X86_FEATURE_PKU, 7, 0, CPUID_ECX, 3);

	check_cpu_has(X86_FEATURE_NPT, 0x8000000a, CPUID_EDX, 0);
	check_cpu_has(X86_FEATURE_LBRV, 0x8000000a, CPUID_EDX, 1);
	check_cpu_has(X86_FEATURE_NRIPS, 0x8000000a, CPUID_EDX, 3);
	check_cpu_has(X86_FEATURE_FLUSHBYASID, 0x8000000a, CPUID_EDX, 6);
	check_cpu_has(X86_FEATURE_DECODEASSISTS, 0x8000000a, CPUID_EDX, 7);
	check_cpu_has(X86_FEATURE_AVIC, 0x8000000a, CPUID_EDX, 13);

	check_cpu_has_ex(X86_FEATURE_XSAVES, 0xd, 1, CPUID_EAX, 3);
}

static NTSTATUS prepare_boot_cpu_data(void)
{
	/* Check Physical Address Bit*/
	unsigned int eax, ebx, ecx, edx;

	boot_cpu_data.extended_cpuid_level = cpuid_eax(0x80000000);
	boot_cpu_data.x86_phys_bits = 36;

	cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
	if (boot_cpu_data.extended_cpuid_level >= 0x80000008)
		if (edx & (1 << 29)) {
			cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
			boot_cpu_data.x86_phys_bits = eax & 0xFF;
		}

	return STATUS_SUCCESS;
}

#define RegName L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory"
static NTSTATUS get_physical_memsize(u64 *size)
{
	OBJECT_ATTRIBUTES keyAttribute;
	UNICODE_STRING keyName, valName;
	HANDLE keyHandle;
	NTSTATUS rc;
	ULONG buffSize, count;
	PKEY_VALUE_FULL_INFORMATION buff;
	PCM_RESOURCE_LIST res;
	PCM_PARTIAL_RESOURCE_LIST list;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR pres;

	RtlInitUnicodeString(&keyName, RegName);
	InitializeObjectAttributes(&keyAttribute,
				   &keyName,
				   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL,
				   NULL);
	rc = ZwOpenKey(&keyHandle, KEY_READ, &keyAttribute);
	if (!NT_SUCCESS(rc))
		return rc;

	RtlInitUnicodeString(&valName, L".Translated");
	rc = ZwQueryValueKey(keyHandle,
			     &valName,
			     KeyValueFullInformation,
			     NULL,
			     0,
			     &buffSize);
	if (!(rc == STATUS_BUFFER_TOO_SMALL ||
	    rc == STATUS_BUFFER_OVERFLOW))
		goto key_close;

	buff = ExAllocatePoolWithTag(NonPagedPool, buffSize, AEHD_POOL_TAG);
	if (!buff) {
		rc = STATUS_NO_MEMORY;
		goto key_close;
	}

	RtlZeroMemory(buff, buffSize);
	rc = ZwQueryValueKey(keyHandle,
			     &valName,
			     KeyValueFullInformation,
			     buff,
			     buffSize,
			     &buffSize);
	if (!NT_SUCCESS(rc))
		goto free_buff;

	ASSERT(buff->Type == REG_RESOURCE_LIST);
	res = (PCM_RESOURCE_LIST)((char *)buff + buff->DataOffset);
	ASSERT(res->Count == 1);
	list = &res->List[0].PartialResourceList;
	count = list->Count;
	pres = &list->PartialDescriptors[count - 1];

	switch (pres->Type) {
	case CmResourceTypeMemory:
		*size = pres->u.Memory.Start.QuadPart +
			pres->u.Memory.Length;
		break;
	case CmResourceTypeMemoryLarge:
		switch (pres->Flags) {
		case CM_RESOURCE_MEMORY_LARGE_40:
			*size = pres->u.Memory40.Start.QuadPart +
				((u64)pres->u.Memory40.Length40 << 8);
			break;
		case CM_RESOURCE_MEMORY_LARGE_48:
			*size = pres->u.Memory48.Start.QuadPart +
				((u64)pres->u.Memory48.Length48 << 16);
			break;
		case CM_RESOURCE_MEMORY_LARGE_64:
			*size = pres->u.Memory64.Start.QuadPart +
				((u64)pres->u.Memory64.Length64 << 32);
			break;
		}
		break;
	}

	rc = STATUS_SUCCESS;

 free_buff:
	ExFreePoolWithTag(buff, AEHD_POOL_TAG);
 key_close:
	ZwClose(keyHandle);
	return rc;
}

/*
 * Init/Deinit Nt Kernel Support Routines
 */

NTSTATUS NtKrUtilsInit(void)
{
	u64 phy_memsize = 0;
	UNICODE_STRING FuncName;
	NTSTATUS rc;
	int cpu;
	PROCESSOR_NUMBER cpu_number;
	unsigned int eax;

	RtlZeroBytes(CPUString, 13);
	cpuid(0, &eax,
	      (unsigned int *)&CPUString[0],
	      (unsigned int *)&CPUString[8],
	      (unsigned int *)&CPUString[4]);

	cpu_features_init();

	rc = get_physical_memsize(&phy_memsize);
	if (!NT_SUCCESS(rc))
		return rc;
	max_pagen = (phy_memsize >> PAGE_SHIFT) + 1;

	rc = prepare_boot_cpu_data();
	if (!NT_SUCCESS(rc))
		return rc;

	rc = aehdGetCpuOnlineMap();
	if (!NT_SUCCESS(rc))
		return rc;

	// Prepare smp call function stuffs
	RtlInitUnicodeString(&FuncName, L"HalRequestIpi");
	pHalRequestIpi = MmGetSystemRoutineAddress(&FuncName);
	RtlInitUnicodeString(&FuncName, L"KeInitializeAffinityEx");
	pKeInitializeAffinityEx = MmGetSystemRoutineAddress(&FuncName);
	RtlInitUnicodeString(&FuncName, L"KeAddProcessorAffinityEx");
	pKeAddProcessorAffinityEx = MmGetSystemRoutineAddress(&FuncName);
	for (cpu = 0; cpu < cpu_online_count; cpu++) {
		KeInitializeDpc(&per_cpu(cpu, ipi_dpc),
				sfc_dpc_routine, NULL);
		rc = KeGetProcessorNumberFromIndex(cpu, &cpu_number);
		if (!NT_SUCCESS(rc))
			return rc;
		rc = KeSetTargetProcessorDpcEx(
				&per_cpu(cpu, ipi_dpc),
				&cpu_number);
		if (!NT_SUCCESS(rc))
			return rc;
		KeSetImportanceDpc(&per_cpu(cpu, ipi_dpc),
					    HighImportance);
	}

	pglist = (struct page**)ExAllocatePoolWithTag(NonPagedPool,
				max_pagen*sizeof(struct page *),
				AEHD_POOL_TAG);
	if (!pglist)
		return STATUS_NO_MEMORY;

	RtlZeroMemory(pglist, max_pagen*sizeof(struct page *));
	INIT_LIST_HEAD(&aehd_mmap_list);
	spin_lock_init(&aehd_mmap_lock);

	return STATUS_SUCCESS;
}

void NtKrUtilsExit(void)
{
	u64 i;

	/* Well implemented code won't rely on freeing here */
	for (i = 0; i < max_pagen; i++)
		if (pglist[i])
			ExFreePoolWithTag(pglist[i], AEHD_POOL_TAG);
	ExFreePoolWithTag(pglist, AEHD_POOL_TAG);
	pglist = NULL;
}

