/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 * Copyright 2019 Google LLC
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <kvm/iodev.h>

#include <linux/kvm_host.h>
#include <uapi/linux/kvm.h>
#include <ntkrutils.h>
#include <gvm-main.h>

/* Worst case buffer size needed for holding an integer. */
#define ITOA_MAX_LEN 12

/*
 * Ordering of locks:
 *
 *	kvm->lock --> kvm->slots_lock --> kvm->irq_lock
 */

DEFINE_SPINLOCK(kvm_lock);
static DEFINE_RAW_SPINLOCK(kvm_count_lock);
LIST_HEAD(vm_list);
static LONG64 global_vm_id = -1;

static cpumask_var_t cpus_hardware_enabled;
static int kvm_usage_count;
static atomic_t hardware_enable_failed;

struct kmem_cache *kvm_vcpu_cache;

static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void kvm_io_bus_destroy(struct kvm_io_bus *bus);

void kvm_release_pfn_dirty(kvm_pfn_t pfn);
static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot, gfn_t gfn);

/*
* bsearch - binary search an array of elements
* @key: pointer to item being searched for
* @base: pointer to first element to search
* @num: number of elements
* @size: size of each element
* @cmp: pointer to comparison function
*
* This function does a binary search on the given array.  The
* contents of the array should already be in ascending sorted order
* under the provided comparison function.
*
* Note that the key need not have the same type as the elements in
* the array, e.g. key could be a string and the comparison function
* could compare the string with the struct's name field.  However, if
* the key and elements in the array are of the same type, you can use
* the same comparison function for both sort() and bsearch().
*/
void *bsearch(const void *key, const void *base, size_t num, size_t size,
	int(*cmp)(const void *key, const void *elt))
{
	size_t start = 0, end = num;
	int result;
	const char *__base = base;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = cmp(key, __base + mid * size);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)(__base + mid * size);
	}

	return NULL;
}

static void generic_swap(void *a, void *b, int size)
{
	char t;
	char *__a = a, *__b = b;

	do {
		t = *__a;
		*__a++ = *__b;
		*__b++ = t;
	} while (--size > 0);
}

/**
* sort - sort an array of elements
* @base: pointer to data to sort
* @num: number of elements
* @size: size of each element
* @cmp_func: pointer to comparison function
* @swap_func: pointer to swap function or NULL
*
* This function does a heapsort on the given array. You may provide a
* swap_func function optimized to your element type.
*
* Sorting time is O(n log n) both on average and worst-case. While
* qsort is about 20% faster on average, it suffers from exploitable
* O(n*n) worst-case behavior and extra memory requirements that make
* it less suitable for kernel use.
*/

static void sort(void *base, size_t num, size_t size,
	int(*cmp_func)(const void *, const void *),
	void(*swap_func)(void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num / 2 - 1) * size, n = num * size, c, r;
	char *__base = base;

	if (!swap_func) {
		swap_func = generic_swap;
}

	/* heapify */
	for (; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r = c) {
			c = r * 2 + size;
			if (c < n - size &&
				cmp_func(__base + c, __base + c + size) < 0)
				c += size;
			if (cmp_func(__base + r, __base + c) >= 0)
				break;
			swap_func(__base + r, __base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size) {
		swap_func(__base, __base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size &&
				cmp_func(__base + c, __base + c + size) < 0)
				c += size;
			if (cmp_func(__base + r, __base + c) >= 0)
				break;
			swap_func(__base + r, __base + c, size);
		}
	}
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
int vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu;

	mutex_lock(&vcpu->mutex);
	cpu = get_cpu();
	kvm_arch_vcpu_load(vcpu, cpu);
	return cpu;
}

void vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_put(vcpu);
	put_cpu();
	mutex_unlock(&vcpu->mutex);
}

void ack_flush(void *_completed)
{
}

bool kvm_make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i, cpu, me;
	cpumask_var_t cpus;
	bool called = true;
	struct kvm_vcpu *vcpu;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = smp_processor_id();
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode. */
		smp_mb__after_atomic();

		if (cpus != NULL && cpu != -1 && cpu != me &&
		      kvm_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE)
			cpumask_set_cpu(cpu, cpus);
	}
	if (unlikely(cpus == NULL))
		smp_call_function_many(cpu_online_mask, ack_flush, NULL, 1);
	else if (!cpumask_empty(cpus))
		smp_call_function_many(cpus, ack_flush, NULL, 1);
	else
		called = false;
	free_cpumask_var(cpus);
	return called;
}

void kvm_flush_remote_tlbs(struct kvm *kvm)
{
	/*
	 * Read tlbs_dirty before setting GVM_REQ_TLB_FLUSH in
	 * kvm_make_all_cpus_request.
	 */
	long dirty_count;
	READ_ONCE(kvm->tlbs_dirty, dirty_count);

	/*
	 * We want to publish modifications to the page tables before reading
	 * mode. Pairs with a memory barrier in arch-specific code.
	 * - x86: smp_mb__after_srcu_read_unlock in vcpu_enter_guest
	 * and smp_mb in walk_shadow_page_lockless_begin/end.
	 * - powerpc: smp_mb in kvmppc_prepare_to_enter.
	 *
	 * There is already an smp_mb__after_atomic() before
	 * kvm_make_all_cpus_request() reads vcpu->mode. We reuse that
	 * barrier here.
	 */
	if (kvm_make_all_cpus_request(kvm, GVM_REQ_TLB_FLUSH))
		++kvm->stat.remote_tlb_flush;
	cmpxchg(&kvm->tlbs_dirty, dirty_count, 0);
}

void kvm_reload_remote_mmus(struct kvm *kvm)
{
	kvm_make_all_cpus_request(kvm, GVM_REQ_MMU_RELOAD);
}

void kvm_vcpu_run_timer_func(KDPC *dpc, void* context, void *arg1, void *arg2)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)context;
	vcpu->run->user_event_pending = 1;
}

int kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->thread = NULL;

	vcpu->pre_pcpu = -1;
	INIT_LIST_HEAD(&vcpu->blocked_vcpu_list);

	/*
	 * KVM(Lin) allocates two seperate pages for vcpu->run and MMIO Emulation page
	 * vcpu->arch.piodata. These two pages will be mapped to userland as continuous
	 * virtual address space. Linux API allows to do that but I did not find a
	 * Windows equivalent API. So keep the physical pages also continuous.
	 */
	vcpu->run = ExAllocatePoolWithTag(NonPagedPool, 2 * PAGE_SIZE, GVM_POOL_TAG);
	if (!vcpu->run) {
		r = -ENOMEM;
		goto fail;
	}
	memset(vcpu->run, 0, 2 * PAGE_SIZE);

	vcpu->preempted = false;

	KeInitializeEvent(&vcpu->kick_event, SynchronizationEvent, FALSE);
	KeInitializeTimer(&vcpu->run_timer);
	KeInitializeDpc(&vcpu->run_timer_dpc, kvm_vcpu_run_timer_func, vcpu);

	r = kvm_arch_vcpu_init(vcpu);
	if (r < 0)
		goto fail_free_run;
	return 0;

fail_free_run:
	ExFreePoolWithTag(vcpu->run, GVM_POOL_TAG);
fail:
	return r;
}

void kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_uninit(vcpu);
	if (vcpu->run_userva)
		__vm_munmap(vcpu->run_userva, 2 * PAGE_SIZE, false);
	ExFreePoolWithTag(vcpu->run, GVM_POOL_TAG);
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(GVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return container_of(mn, struct kvm, mmu_notifier);
}

static void kvm_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
					     struct mm_struct *mm,
					     size_t address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush, idx;

	/*
	 * When ->invalidate_page runs, the linux pte has been zapped
	 * already but the page is still allocated until
	 * ->invalidate_page returns. So if we increase the sequence
	 * here the kvm page fault will notice if the spte can't be
	 * established because the page is going to be freed. If
	 * instead the kvm page fault establishes the spte before
	 * ->invalidate_page runs, kvm_unmap_hva will release it
	 * before returning.
	 *
	 * The sequence increase only need to be seen at spin_unlock
	 * time, and not at spin_lock time.
	 *
	 * Increasing the sequence after the spin_unlock would be
	 * unsafe because the kvm page fault could then establish the
	 * pte after kvm_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	kvm->mmu_notifier_seq++;
	need_tlb_flush = kvm_unmap_hva(kvm, address) | kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);

	kvm_arch_mmu_notifier_invalidate_page(kvm, address);

	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					size_t address,
					pte_t pte)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    size_t start,
						    size_t end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush = 0, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	need_tlb_flush = kvm_unmap_hva_range(kvm, start, end);
	need_tlb_flush |= kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  size_t start,
						  size_t end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	spin_lock(&kvm->mmu_lock);
	/*
	 * This sequence increase will notify the kvm page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	kvm->mmu_notifier_seq++;
	smp_wmb();
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease, which is ensured by the smp_wmb above
	 * in conjunction with the smp_rmb in mmu_notifier_retry().
	 */
	kvm->mmu_notifier_count--;
	spin_unlock(&kvm->mmu_lock);

	BUG_ON(kvm->mmu_notifier_count < 0);
}

static int kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      size_t start,
					      size_t end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	young = kvm_age_hva(kvm, start, end);
	if (young)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					size_t start,
					size_t end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * Even though we do not flush TLB, this will still adversely
	 * affect performance on pre-Haswell Intel EPT, where there is
	 * no EPT Access Bit to clear so that we have to tear down EPT
	 * tables instead. If we find this unacceptable, we can always
	 * add a parameter to kvm_age_hva so that it effectively doesn't
	 * do anything on clear_young.
	 *
	 * Also note that currently we never issue secondary TLB flushes
	 * from clear_young, leaving this job up to the regular system
	 * cadence. If we find this inaccurate, we might come up with a
	 * more sophisticated heuristic later.
	 */
	young = kvm_age_hva(kvm, start, end);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       size_t address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	young = kvm_test_age_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow_all(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.invalidate_page	= kvm_mmu_notifier_invalidate_page,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.clear_young		= kvm_mmu_notifier_clear_young,
	.test_young		= kvm_mmu_notifier_test_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
	.release		= kvm_mmu_notifier_release,
};

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, current->mm);
}

#else  /* !(CONFIG_MMU_NOTIFIER && GVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && GVM_ARCH_WANT_MMU_NOTIFIER */

static struct kvm_memslots *kvm_alloc_memslots(void)
{
	int i;
	struct kvm_memslots *slots;

	slots = kvm_kvzalloc(sizeof(struct kvm_memslots));
	if (!slots)
		return NULL;

	/*
	 * Init kvm generation close to the maximum to easily test the
	 * code of handling generation number wrap-around.
	 */
	slots->generation = -150;
	for (i = 0; i < GVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = slots->memslots[i].id = i;

	return slots;
}

static void kvm_destroy_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

/*
 * Free any memory in @free but not in @dont.
 */
static void kvm_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			      struct kvm_memory_slot *dont)
{
	struct pmem_lock *pl;
	int i;

	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		kvm_destroy_dirty_bitmap(free);

	if (!dont || free->pmem_lock != dont->pmem_lock)
		if (free->pmem_lock) {
			for (i = 0; i < free->npages; i++) {
				pl = &free->pmem_lock[i];
				if (!pl->lock_mdl)
					continue;
				spin_lock(&pl->lock);
				MmUnlockPages(pl->lock_mdl);
				IoFreeMdl(pl->lock_mdl);
				pl->lock_mdl = NULL;
				spin_unlock(&pl->lock);
			}
			kfree(free->pmem_lock);
		}

	kvm_arch_free_memslot(kvm, free, dont);

	free->npages = 0;
}

static void kvm_free_memslots(struct kvm *kvm, struct kvm_memslots *slots)
{
	struct kvm_memory_slot *memslot;

	if (!slots)
		return;

	kvm_for_each_memslot(memslot, slots)
		kvm_free_memslot(kvm, memslot, NULL);

	kvfree(slots);
}

static struct kvm *kvm_create_vm(size_t type)
{
	int r, i;
	struct kvm *kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&kvm->mmu_lock);
	kvm->process = IoGetCurrentProcess();
	kvm->vm_id = InterlockedIncrement64(&global_vm_id);
	mutex_init(&kvm->lock);
	mutex_init(&kvm->irq_lock);
	mutex_init(&kvm->slots_lock);
	atomic_set(&kvm->users_count, 1);

	r = kvm_arch_init_vm(kvm, type);
	if (r)
		goto out_err_no_disable;

	r = hardware_enable_all();
	if (r)
		goto out_err_no_disable;

	r = -ENOMEM;
	for (i = 0; i < GVM_ADDRESS_SPACE_NUM; i++) {
		kvm->memslots[i] = kvm_alloc_memslots();
		if (!kvm->memslots[i])
			goto out_err_no_srcu;
	}

	if (init_srcu_struct(&kvm->srcu))
		goto out_err_no_srcu;
	if (init_srcu_struct(&kvm->irq_srcu))
		goto out_err_no_irq_srcu;
	for (i = 0; i < GVM_NR_BUSES; i++) {
		kvm->buses[i] = kzalloc(sizeof(struct kvm_io_bus),
					GFP_KERNEL);
		if (!kvm->buses[i])
			goto out_err;
	}

	r = kvm_init_mmu_notifier(kvm);
	if (r)
		goto out_err;

	spin_lock(&kvm_lock);
	list_add(&kvm->vm_list, &vm_list);
	spin_unlock(&kvm_lock);

	return kvm;

out_err:
	cleanup_srcu_struct(&kvm->irq_srcu);
out_err_no_irq_srcu:
	cleanup_srcu_struct(&kvm->srcu);
out_err_no_srcu:
	hardware_disable_all();
out_err_no_disable:
	for (i = 0; i < GVM_NR_BUSES; i++)
		kfree(kvm->buses[i]);
	for (i = 0; i < GVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, kvm->memslots[i]);
	kvm_arch_free_vm(kvm);
	return ERR_PTR(r);
}

/*
 * Avoid using vmalloc for a small buffer.
 * Should not be used when the size is statically known.
 */
void *kvm_kvzalloc(size_t size)
{
	if (size > PAGE_SIZE)
		return vzalloc(size);
	else
		return kzalloc(size, GFP_KERNEL);
}

static void kvm_destroy_vm(struct kvm *kvm)
{
	int i;

	spin_lock(&kvm_lock);
	list_del(&kvm->vm_list);
	spin_unlock(&kvm_lock);
	kvm_free_irq_routing(kvm);
	for (i = 0; i < GVM_NR_BUSES; i++)
		kvm_io_bus_destroy(kvm->buses[i]);
	kvm_arch_flush_shadow_all(kvm);
	kvm_arch_destroy_vm(kvm);
	for (i = 0; i < GVM_ADDRESS_SPACE_NUM; i++)
		kvm_free_memslots(kvm, kvm->memslots[i]);
	cleanup_srcu_struct(&kvm->irq_srcu);
	cleanup_srcu_struct(&kvm->srcu);
	kvm_arch_free_vm(kvm);
	hardware_disable_all();
}

void kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc(&kvm->users_count);
}

void kvm_put_kvm(struct kvm *kvm)
{
	if (atomic_dec_and_test(&kvm->users_count))
		kvm_destroy_vm(kvm);
}


NTSTATUS kvm_vm_release(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm *kvm = devext->PrivData;

	kvm_put_kvm(kvm);
	return 0;
}

/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * See x86's kvm_vm_ioctl_get_dirty_log() why this is needed.
 */
static int kvm_create_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	size_t dirty_bytes = 2 * kvm_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = kvm_kvzalloc(dirty_bytes);
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

/*
 * Insert memslot and re-sort memslots based on their GFN,
 * so binary search could be used to lookup GFN.
 * Sorting algorithm takes advantage of having initially
 * sorted array and known changed memslot position.
 */
static void update_memslots(struct kvm_memslots *slots,
			    struct kvm_memory_slot *new)
{
	int id = new->id;
	int i = slots->id_to_index[id];
	struct kvm_memory_slot *mslots = slots->memslots;

	WARN_ON(mslots[i].id != id);
	if (!new->npages) {
		WARN_ON(!mslots[i].npages);
		if (mslots[i].npages)
			slots->used_slots--;
	} else {
		if (!mslots[i].npages)
			slots->used_slots++;
	}

	while (i < GVM_MEM_SLOTS_NUM - 1 &&
	       new->base_gfn <= mslots[i + 1].base_gfn) {
		if (!mslots[i + 1].npages)
			break;
		mslots[i] = mslots[i + 1];
		slots->id_to_index[mslots[i].id] = i;
		i++;
	}

	/*
	 * The ">=" is needed when creating a slot with base_gfn == 0,
	 * so that it moves before all those with base_gfn == npages == 0.
	 *
	 * On the other hand, if new->npages is zero, the above loop has
	 * already left i pointing to the beginning of the empty part of
	 * mslots, and the ">=" would move the hole backwards in this
	 * case---which is wrong.  So skip the loop when deleting a slot.
	 */
	if (new->npages) {
		while (i > 0 &&
		       new->base_gfn >= mslots[i - 1].base_gfn) {
			mslots[i] = mslots[i - 1];
			slots->id_to_index[mslots[i].id] = i;
			i--;
		}
	} else
		WARN_ON_ONCE(i != slots->used_slots);

	mslots[i] = *new;
	slots->id_to_index[mslots[i].id] = i;
}

static int check_memory_region_flags(const struct kvm_userspace_memory_region *mem)
{
	u32 valid_flags = GVM_MEM_LOG_DIRTY_PAGES;

#ifdef __GVM_HAVE_READONLY_MEM
	valid_flags |= GVM_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

static struct kvm_memslots *install_new_memslots(struct kvm *kvm,
		int as_id, struct kvm_memslots *slots)
{
	struct kvm_memslots *old_memslots = __kvm_memslots(kvm, as_id);

	/*
	 * Set the low bit in the generation, which disables SPTE caching
	 * until the end of synchronize_srcu_expedited.
	 */
	WARN_ON(old_memslots->generation & 1);
	slots->generation = old_memslots->generation + 1;

	rcu_assign_pointer(kvm->memslots[as_id], slots);
	synchronize_srcu_expedited(&kvm->srcu);

	/*
	 * Increment the new memslot generation a second time. This prevents
	 * vm exits that race with memslot updates from caching a memslot
	 * generation that will (potentially) be valid forever.
	 */
	slots->generation++;

	kvm_arch_memslots_updated(kvm, slots);

	return old_memslots;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding kvm->slots_lock for write.
 */
int __kvm_set_memory_region(struct kvm *kvm,
			    const struct kvm_userspace_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	size_t npages;
	struct kvm_memory_slot *slot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots = NULL, *old_memslots;
	int as_id, id;
	enum kvm_mr_change change;

	r = check_memory_region_flags(mem);
	if (r)
		goto out;

	r = -EINVAL;
	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	if (as_id >= GVM_ADDRESS_SPACE_NUM || id >= GVM_MEM_SLOTS_NUM)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	slot = id_to_memslot(__kvm_memslots(kvm, as_id), id);
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	if (npages > GVM_MEM_MAX_NR_PAGES)
		goto out;

	new = old = *slot;

	new.id = id;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	if (npages) {
		if (!old.npages)
			change = GVM_MR_CREATE;
		else { /* Modify an existing slot. */
			if ((mem->userspace_addr != old.userspace_addr) ||
			    (npages != old.npages) ||
			    ((new.flags ^ old.flags) & GVM_MEM_READONLY))
				goto out;

			if (base_gfn != old.base_gfn)
				change = GVM_MR_MOVE;
			else if (new.flags != old.flags)
				change = GVM_MR_FLAGS_ONLY;
			else { /* Nothing to change. */
				r = 0;
				goto out;
			}
		}
	} else {
		if (!old.npages)
			goto out;

		change = GVM_MR_DELETE;
		new.base_gfn = 0;
		new.flags = 0;
	}

	if ((change == GVM_MR_CREATE) || (change == GVM_MR_MOVE)) {
		/* Check for overlaps */
		r = -EEXIST;
		kvm_for_each_memslot(slot, __kvm_memslots(kvm, as_id)) {
			if ((slot->id >= GVM_USER_MEM_SLOTS) ||
			    (slot->id == id))
				continue;
			if (!((base_gfn + npages <= slot->base_gfn) ||
			      (base_gfn >= slot->base_gfn + slot->npages)))
				goto out;
		}
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & GVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = -ENOMEM;
	if (change == GVM_MR_CREATE) {
		new.userspace_addr = mem->userspace_addr;

		if (kvm_arch_create_memslot(kvm, &new, npages))
			goto out_free;

	}

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & GVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (kvm_create_dirty_bitmap(&new) < 0)
			goto out_free;
	}

	/* Allocate physical page pinning data structure */
	if (!new.pmem_lock) {
		new.pmem_lock =
		       	kzalloc(sizeof(struct pmem_lock) * new.npages, GFP_KERNEL);
		if (!new.pmem_lock)
			goto out_free;
	}

	slots = kvm_kvzalloc(sizeof(struct kvm_memslots));
	if (!slots)
		goto out_free;
	memcpy(slots, __kvm_memslots(kvm, as_id), sizeof(struct kvm_memslots));

	if ((change == GVM_MR_DELETE) || (change == GVM_MR_MOVE)) {
		slot = id_to_memslot(slots, id);
		slot->flags |= GVM_MEMSLOT_INVALID;

		old_memslots = install_new_memslots(kvm, as_id, slots);

		/* From this point no new shadow pages pointing to a deleted,
		 * or moved, memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 *	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 *	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow_memslot(kvm, slot);

		/*
		 * We can re-use the old_memslots from above, the only difference
		 * from the currently installed memslots is the invalid flag.  This
		 * will get overwritten by update_memslots anyway.
		 */
		slots = old_memslots;
	}

	r = kvm_arch_prepare_memory_region(kvm, &new, mem, change);
	if (r)
		goto out_slots;

	/* actual memory is freed via old in kvm_free_memslot below */
	if (change == GVM_MR_DELETE) {
		new.dirty_bitmap = NULL;
		new.pmem_lock = NULL;
		memset(&new.arch, 0, sizeof(new.arch));
	}

	update_memslots(slots, &new);
	old_memslots = install_new_memslots(kvm, as_id, slots);

	kvm_arch_commit_memory_region(kvm, mem, &old, &new, change);

	kvm_free_memslot(kvm, &old, &new);
	kvfree(old_memslots);

	return 0;

out_slots:
	kvfree(slots);
out_free:
	kvm_free_memslot(kvm, &new, &old);
out:
	return r;
}

int kvm_set_memory_region(struct kvm *kvm,
			  const struct kvm_userspace_memory_region *mem)
{
	int r;

	mutex_lock(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem);
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
					  struct kvm_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= GVM_USER_MEM_SLOTS)
		return -EINVAL;

	return kvm_set_memory_region(kvm, mem);
}

int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int r, i, as_id, id;
	size_t n;
	size_t any = 0;

	r = -EINVAL;
	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= GVM_ADDRESS_SPACE_NUM || id >= GVM_USER_MEM_SLOTS)
		goto out;

	slots = __kvm_memslots(kvm, as_id);
	memslot = id_to_memslot(slots, id);
	r = -ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	for (i = 0; !any && i < n/sizeof(long); ++i)
		any = memslot->dirty_bitmap[i];

	r = -EFAULT;
	if ( __copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
		goto out;

	if (any)
		*is_dirty = 1;

	r = 0;
out:
	return r;
}

/**
 * kvm_get_dirty_log_protect - get a snapshot of dirty pages, and if any pages
 *	are dirty write protect them for next write.
 * @kvm:	pointer to kvm instance
 * @log:	slot id and address to which we copy the log
 * @is_dirty:	flag set if any page is dirty
 *
 * We need to keep it in mind that VCPU threads can write to the bitmap
 * concurrently. So, to avoid losing track of dirty pages we keep the
 * following order:
 *
 *    1. Take a snapshot of the bit and clear it if needed.
 *    2. Write protect the corresponding page.
 *    3. Copy the snapshot to the userspace.
 *    4. Upon return caller flushes TLB's if needed.
 *
 * Between 2 and 4, the guest may write to the page using the remaining TLB
 * entry.  This is not a problem because the page is reported dirty using
 * the snapshot taken before and step 4 ensures that writes done after
 * exiting to userspace will be logged for the next call.
 *
 */
int kvm_get_dirty_log_protect(struct kvm *kvm,
			struct kvm_dirty_log *log, bool *is_dirty)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int r, i, as_id, id;
	size_t n;
	size_t *dirty_bitmap;
	size_t *dirty_bitmap_buffer;

	r = -EINVAL;
	as_id = log->slot >> 16;
	id = (u16)log->slot;
	if (as_id >= GVM_ADDRESS_SPACE_NUM || id >= GVM_USER_MEM_SLOTS)
		goto out;

	slots = __kvm_memslots(kvm, as_id);
	memslot = id_to_memslot(slots, id);

	dirty_bitmap = memslot->dirty_bitmap;
	r = -ENOENT;
	if (!dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	dirty_bitmap_buffer = dirty_bitmap + n / sizeof(size_t);
	memset(dirty_bitmap_buffer, 0, n);

	spin_lock(&kvm->mmu_lock);
	*is_dirty = false;
	for (i = 0; i < n / sizeof(size_t); i++) {
		size_t mask;
		gfn_t offset;

		if (!dirty_bitmap[i])
			continue;

		*is_dirty = true;

		mask = xchg(&dirty_bitmap[i], 0);
		dirty_bitmap_buffer[i] = mask;

		if (mask) {
			offset = i * BITS_PER_LONG;
			kvm_arch_mmu_enable_log_dirty_pt_masked(kvm, memslot,
								offset, mask);
		}
	}

	spin_unlock(&kvm->mmu_lock);

	r = -EFAULT;
	if ( __copy_to_user(log->dirty_bitmap, dirty_bitmap_buffer, n))
		goto out;

	r = 0;
out:
	return r;
}

struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_memslots(kvm), gfn);
}

struct kvm_memory_slot *kvm_vcpu_gfn_to_memslot(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_vcpu_memslots(vcpu), gfn);
}

bool kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot = gfn_to_memslot(kvm, gfn);

	if (!memslot || memslot->id >= GVM_USER_MEM_SLOTS ||
	      memslot->flags & GVM_MEMSLOT_INVALID)
		return false;

	return true;
}

size_t kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	return PAGE_SIZE;
}

static bool memslot_is_readonly(struct kvm_memory_slot *slot)
{
	return slot->flags & GVM_MEM_READONLY;
}

static size_t __gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
	if (!slot || slot->flags & GVM_MEMSLOT_INVALID)
		return GVM_HVA_ERR_BAD;

	if (memslot_is_readonly(slot) && write)
		return GVM_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

	return __gfn_to_hva_memslot(slot, gfn);
}

static size_t gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				     gfn_t *nr_pages)
{
	return __gfn_to_hva_many(slot, gfn, nr_pages, true);
}

size_t gfn_to_hva_memslot(struct kvm_memory_slot *slot,
					gfn_t gfn)
{
	return gfn_to_hva_many(slot, gfn, NULL);
}

size_t gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_hva_many(gfn_to_memslot(kvm, gfn), gfn, NULL);
}

size_t kvm_vcpu_gfn_to_hva(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_hva_many(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn, NULL);
}

/*
 * If writable is set to false, the hva returned by this function is only
 * allowed to be read.
 */
size_t gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot,
				      gfn_t gfn, bool *writable)
{
	size_t hva = __gfn_to_hva_many(slot, gfn, NULL, false);

	if (!kvm_is_error_hva(hva) && writable)
		*writable = !memslot_is_readonly(slot);

	return hva;
}

size_t gfn_to_hva_prot(struct kvm *kvm, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

size_t kvm_vcpu_gfn_to_hva_prot(struct kvm_vcpu *vcpu, gfn_t gfn, bool *writable)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return gfn_to_hva_memslot_prot(slot, gfn, writable);
}

/*
 * The atomic path to get the writable pfn which will be stored in @pfn,
 * true indicates success, otherwise false is returned.
 */
static bool __hva_to_pfn(size_t addr,
			    bool write_fault, bool *writable, kvm_pfn_t *pfn)
{
	if (writable)
		*writable = write_fault;

	/* map read fault as writable if possible */
	if (!write_fault && writable)
		*writable = true;

	*pfn = __pa((void *)addr) >> PAGE_SHIFT;

	return true;
}

/*
 * Pin guest page in memory and return its pfn.
 * @addr: host virtual address which maps memory to the guest
 * @atomic: whether this function can sleep
 * @async: whether this function need to wait IO complete if the
 *         host page is not in the memory
 * @write_fault: whether we should get a writable host page
 * @writable: whether it allows to map a writable host page for !@write_fault
 *
 * The function will map a writable host page for these two cases:
 * 1): @write_fault = true
 * 2): @write_fault = false && @writable, @writable will tell the caller
 *     whether the mapping is writable.
 */
static kvm_pfn_t hva_to_pfn(size_t addr,
			bool write_fault, bool *writable)
{
	kvm_pfn_t pfn = 0;

	if (__hva_to_pfn(addr, write_fault, writable, &pfn))
		return pfn;

	return GVM_PFN_ERR_FAULT;
}

static int gvm_pin_user_memory(size_t addr, struct pmem_lock *pmem_lock)
{
	pmem_lock->lock_mdl = IoAllocateMdl((PVOID)addr, PAGE_SIZE,
			FALSE, FALSE, NULL);
	if (!pmem_lock->lock_mdl)
		return -1;
	MmProbeAndLockPages(pmem_lock->lock_mdl, UserMode,
			IoWriteAccess);
	return 0;
}

kvm_pfn_t __gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool *async, bool write_fault,
			       bool *writable)
{
	size_t addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);
	struct pmem_lock *pmem_lock = NULL;

	/* We removed async pafe fault support for gvm*/
	BUG_ON(async);

	if (addr == GVM_HVA_ERR_RO_BAD) {
		if (writable)
			*writable = false;
		return GVM_PFN_ERR_RO_FAULT;
	}

	if (kvm_is_error_hva(addr)) {
		if (writable)
			*writable = false;
		return GVM_PFN_NOSLOT;
	}

	/* Do not map writable pfn in the readonly memslot. */
	if (writable && memslot_is_readonly(slot)) {
		*writable = false;
		writable = NULL;
	}

	pmem_lock = &slot->pmem_lock[gfn - slot->base_gfn];
	spin_lock(&pmem_lock->lock);
	if (!pmem_lock->lock_mdl) {
		gvm_pin_user_memory(addr, pmem_lock);
		if (!pmem_lock->lock_mdl) {
			spin_unlock(&pmem_lock->lock);
			return GVM_PFN_ERR_FAULT;
		}
	}
	spin_unlock(&pmem_lock->lock);

	return hva_to_pfn(addr, write_fault, writable);
}

kvm_pfn_t gfn_to_pfn_prot(struct kvm *kvm, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return __gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn, false, NULL,
				    write_fault, writable);
}

kvm_pfn_t gfn_to_pfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return __gfn_to_pfn_memslot(slot, gfn, false, NULL, true, NULL);
}

kvm_pfn_t gfn_to_pfn_memslot_atomic(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return __gfn_to_pfn_memslot(slot, gfn, true, NULL, true, NULL);
}

kvm_pfn_t gfn_to_pfn_atomic(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(gfn_to_memslot(kvm, gfn), gfn);
}

kvm_pfn_t kvm_vcpu_gfn_to_pfn_atomic(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot_atomic(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}

kvm_pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_pfn_memslot(gfn_to_memslot(kvm, gfn), gfn);
}

kvm_pfn_t kvm_vcpu_gfn_to_pfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return gfn_to_pfn_memslot(kvm_vcpu_gfn_to_memslot(vcpu, gfn), gfn);
}

int gfn_to_pfn_many_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			    pfn_t *pfn, int nr_pages)
{
	size_t addr;
	gfn_t entry;
	size_t i;
	struct pmem_lock *pmem_lock;

	addr = gfn_to_hva_many(slot, gfn, &entry);
	if (kvm_is_error_hva(addr))
		return -1;

	if (entry < nr_pages)
		return 0;

	for (i = 0; i < nr_pages; i++) {
		pmem_lock = &slot->pmem_lock[gfn + i - slot->base_gfn];
		spin_lock(&pmem_lock->lock);
		if (!pmem_lock->lock_mdl) {
			gvm_pin_user_memory(addr + i * PAGE_SIZE, pmem_lock);
			if (!pmem_lock->lock_mdl) {
				spin_unlock(&pmem_lock->lock);
				break;
			}
		}
		spin_unlock(&pmem_lock->lock);
	}

	nr_pages = i;

	while(i--)
		pfn[i] = __pa((void*)(addr + i * PAGE_SIZE)) >> PAGE_SHIFT;
	return nr_pages;
}

static struct page *kvm_pfn_to_page(kvm_pfn_t pfn)
{
	if (is_error_noslot_pfn(pfn))
		return GVM_ERR_PTR_BAD_PAGE;

	return pfn_to_page(pfn);
}

struct page *kvm_vcpu_gfn_to_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	kvm_pfn_t pfn;

	pfn = kvm_vcpu_gfn_to_pfn(vcpu, gfn);

	return kvm_pfn_to_page(pfn);
}

static int next_segment(size_t len, int offset)
{
	if (len > PAGE_SIZE - offset)
		return PAGE_SIZE - offset;
	else
		return len;
}

static int __kvm_read_guest_page(struct kvm_memory_slot *slot, gfn_t gfn,
				 void *data, int offset, int len)
{
	int r = 0;
	size_t addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_from_user(data, (char __user *)addr + offset, len);
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}

int kvm_vcpu_read_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn, void *data,
			     int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_read_guest_page(slot, gfn, data, offset, len);
}

int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		//data += seg;
		++gfn;
	}
	return 0;
}

int kvm_vcpu_read_guest(struct kvm_vcpu *vcpu, gpa_t gpa, void *data, size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_read_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		//data += seg;
		++gfn;
	}
	return 0;
}

static int __kvm_read_guest_atomic(struct kvm_memory_slot *slot, gfn_t gfn,
			           void *data, int offset, size_t len)
{
	int r = 0;
	size_t addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_from_user(data, (char __user *)addr + offset, len);
	if (r)
		return -EFAULT;
	return 0;
}

int kvm_vcpu_read_guest_atomic(struct kvm_vcpu *vcpu, gpa_t gpa,
			       void *data, size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	int offset = offset_in_page(gpa);

	return __kvm_read_guest_atomic(slot, gfn, data, offset, len);
}

static int __kvm_write_guest_page(struct kvm_memory_slot *memslot, gfn_t gfn,
			          const void *data, int offset, int len)
{
	int r = 0;
	size_t addr;

	addr = gfn_to_hva_memslot(memslot, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_to_user((void __user *)(addr + offset), data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(memslot, gfn);
	return 0;
}

int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn,
			 const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}

int kvm_vcpu_write_guest_page(struct kvm_vcpu *vcpu, gfn_t gfn,
			      const void *data, int offset, int len)
{
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	return __kvm_write_guest_page(slot, gfn, data, offset, len);
}

int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		//data += seg;
		++gfn;
	}
	return 0;
}

int kvm_vcpu_write_guest(struct kvm_vcpu *vcpu, gpa_t gpa, const void *data,
		         size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_vcpu_write_guest_page(vcpu, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		//data += seg;
		++gfn;
	}
	return 0;
}

int kvm_gfn_to_hva_cache_init(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			      gpa_t gpa, size_t len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int offset = offset_in_page(gpa);
	gfn_t start_gfn = gpa >> PAGE_SHIFT;
	gfn_t end_gfn = (gpa + len - 1) >> PAGE_SHIFT;
	gfn_t nr_pages_needed = end_gfn - start_gfn + 1;
	gfn_t nr_pages_avail;

	ghc->gpa = gpa;
	ghc->generation = slots->generation;
	ghc->len = len;
	ghc->memslot = gfn_to_memslot(kvm, start_gfn);
	ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn, NULL);
	if (!kvm_is_error_hva(ghc->hva) && nr_pages_needed <= 1) {
		ghc->hva += offset;
	} else {
		/*
		 * If the requested region crosses two memslots, we still
		 * verify that the entire region is valid here.
		 */
		while (start_gfn <= end_gfn) {
			ghc->memslot = gfn_to_memslot(kvm, start_gfn);
			ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn,
						   &nr_pages_avail);
			if (kvm_is_error_hva(ghc->hva))
				return -EFAULT;
			start_gfn += nr_pages_avail;
		}
		/* Use the slow path for cross page reads and writes. */
		ghc->memslot = NULL;
	}
	return 0;
}

int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, size_t len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_write_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_to_user((void __user *)ghc->hva, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(ghc->memslot, ghc->gpa >> PAGE_SHIFT);

	return 0;
}

int kvm_read_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, size_t len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_read_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_from_user(data, (void __user *)ghc->hva, len);
	if (r)
		return -EFAULT;

	return 0;
}

int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	return kvm_write_guest_page(kvm, gfn, pZeroPage, offset, len);
}

int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, size_t len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_clear_guest_page(kvm, gfn, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		++gfn;
	}
	return 0;
}

static void mark_page_dirty_in_slot(struct kvm_memory_slot *memslot,
				    gfn_t gfn)
{
	if (memslot && memslot->dirty_bitmap) {
		size_t rel_gfn = gfn - memslot->base_gfn;

		set_bit(rel_gfn, memslot->dirty_bitmap);
	}
}

void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = gfn_to_memslot(kvm, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}

void kvm_vcpu_mark_page_dirty(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	mark_page_dirty_in_slot(memslot, gfn);
}

static int kvm_vcpu_check_block(struct kvm_vcpu *vcpu)
{
	if (kvm_arch_vcpu_runnable(vcpu)) {
		kvm_make_request(GVM_REQ_UNHALT, vcpu);
		return -EINTR;
	}
	if (kvm_cpu_has_pending_timer(vcpu))
		return -EINTR;
	if (vcpu->run->user_event_pending)
		return -EINTR;

	return 0;
}

static void hardware_disable_nolock(void *junk);
static void hardware_enable_nolock(void *junk);

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	LARGE_INTEGER expire;
	expire.QuadPart = (u64)-1000000;

	kvm_arch_vcpu_blocking(vcpu);

	vcpu->blocked = 1;
	for (;;)
	{
		if (kvm_vcpu_check_block(vcpu))
			break;
		KeWaitForSingleObject(&vcpu->kick_event, Executive, KernelMode, FALSE, &expire);
	}
	vcpu->blocked = 0;
	KeClearEvent(&vcpu->kick_event);
	kvm_arch_vcpu_unblocking(vcpu);
	kvm_arch_vcpu_block_finish(vcpu);
}

void kvm_vcpu_wake_up(struct kvm_vcpu *vcpu)
{
	if(vcpu->blocked)
		KeSetEvent(&vcpu->kick_event, IO_NO_INCREMENT, FALSE);
}

/*
 * Kick a sleeping VCPU, or a guest VCPU in guest mode, into host kernel mode.
 */
void kvm_vcpu_kick(struct kvm_vcpu *vcpu)
{
	int me;
	int cpu = vcpu->cpu;

	kvm_vcpu_wake_up(vcpu);
	me = smp_processor_id();
	if (cpu != -1 && cpu != me && cpu_online(cpu))
		if (kvm_arch_vcpu_should_kick(vcpu))
			smp_send_reschedule(cpu);
}

NTSTATUS kvm_vcpu_release(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm_vcpu *vcpu = devext->PrivData;

	kvm_put_kvm(vcpu->kvm);
	return 0;
}

static int kvm_vm_ioctl_create_vcpu(PDEVICE_OBJECT pDevObj, PIRP pIrp, void *arg)
{
	int r;
	struct kvm_vcpu *vcpu;
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm *kvm = devext->PrivData;
	HANDLE handle;
	int id = *(int *)arg;
	KAFFINITY Affinity;

	mutex_lock(&kvm->lock);
	if (id >= GVM_MAX_VCPU_ID)
		return -EINVAL;

	if (kvm->created_vcpus == GVM_MAX_VCPUS) {
		mutex_unlock(&kvm->lock);
		return -EINVAL;
	}

	kvm->created_vcpus++;
	mutex_unlock(&kvm->lock);

	vcpu = kvm_arch_vcpu_create(kvm, id);
	if (IS_ERR(vcpu)) {
		r = PTR_ERR(vcpu);
		goto vcpu_decrement;
	}

	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

	mutex_lock(&kvm->lock);
	if (kvm_get_vcpu_by_id(kvm, id)) {
		r = -EEXIST;
		goto unlock_vcpu_destroy;
	}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);
	r = gvmCreateVMDevice(&handle, kvm->vm_id, id, vcpu);
	if (!NT_SUCCESS(r)) {
		kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}
	r = gvmUpdateReturnBuffer(pIrp, 0, &handle, sizeof(handle));
	if (r) {
		gvmDeleteVMDevice(NULL, 0, id);
		kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}

	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;

	/*
	 * Pairs with smp_rmb() in kvm_get_vcpu.  Write kvm->vcpus
	 * before kvm->online_vcpu's incremented value.
	 */
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

	mutex_unlock(&kvm->lock);
	kvm_arch_vcpu_postcreate(vcpu);

	if (is_Intel()) {
		Affinity = (KAFFINITY)1 << (
			cpu_online_count - 1
			- 2 * vcpu->vcpu_id / cpu_online_count % 2
			- vcpu->vcpu_id * 2 % cpu_online_count);
		KeSetSystemAffinityThread(Affinity);
	}
	return r;

unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
vcpu_destroy:
	kvm_arch_vcpu_destroy(vcpu);
vcpu_decrement:
	mutex_lock(&kvm->lock);
	kvm->created_vcpus--;
	mutex_unlock(&kvm->lock);
	return r;
}

static int kvm_vm_ioctl_kick_vcpu(PDEVICE_OBJECT pDevObj, PIRP pIrp, void *arg)
{
	struct kvm_vcpu *vcpu;
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm *kvm = devext->PrivData;
	int id = *(int *)arg;

	if (id >= GVM_MAX_VCPU_ID)
		return -EINVAL;

	vcpu = kvm_get_vcpu_by_id(kvm, id);
	if (!vcpu)
		return -EINVAL;

	kvm_vcpu_kick(vcpu);

	return 0;
}

NTSTATUS kvm_vcpu_fast_ioctl_run(PDEVICE_OBJECT pDevObj)
{
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm_vcpu *vcpu = devext->PrivData;
	LARGE_INTEGER expire;
	expire.QuadPart = (u64)-10000000;
	KAFFINITY Affinity;
	int r = -EINVAL;

	if (vcpu->kvm->process != IoGetCurrentProcess())
		return -EIO;

	if (vcpu->thread != PsGetCurrentThread()) {
		vcpu->thread = PsGetCurrentThread();
		KeInitializeApc(&vcpu->apc, vcpu->thread,
				OriginalApcEnvironment,
				gvmWaitSuspend,
				NULL,
				NULL,
				KernelMode,
				NULL);
		if (is_Intel()) {
			Affinity = (KAFFINITY)1 << (
				cpu_online_count - 1
				- 2 * vcpu->vcpu_id / cpu_online_count % 2
				- vcpu->vcpu_id * 2 % cpu_online_count);
			KeSetSystemAffinityThread(Affinity);
		}
	}
	/* vcpu_run has to return to user space periodically otherwise
	 * vcpu thread could hang when process terminates.
	 */
	KeSetTimer(&vcpu->run_timer, expire, &vcpu->run_timer_dpc);

	r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);

	KeCancelTimer(&vcpu->run_timer);
	KeInitializeTimer(&vcpu->run_timer);

	return r;
}

NTSTATUS kvm_vcpu_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp,
			   unsigned int ioctl)
{
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm_vcpu *vcpu = devext->PrivData;
	void __user *argp = (void __user *)pIrp->AssociatedIrp.SystemBuffer;
	int r;
	struct kvm_fpu *fpu = NULL;
	struct kvm_sregs *kvm_sregs = NULL;
	LARGE_INTEGER expire;
	expire.QuadPart = (u64)-10000000;

	if (vcpu->kvm->process != IoGetCurrentProcess())
		return -EIO;

	switch (ioctl) {
	case GVM_RUN:
		r = kvm_vcpu_fast_ioctl_run(pDevObj);
		break;
	case GVM_VCPU_MMAP:
		r = -EINVAL;
		size_t mmap_size = 2 * PAGE_SIZE;
		size_t userva = __vm_mmap(NULL, 0, mmap_size, PROT_READ |PROT_WRITE, 
			MAP_SHARED | MAP_ANONYMOUS, 0, (size_t)vcpu->run);
		if (!userva)
			break;
		r = gvmUpdateReturnBuffer(pIrp, 0, &userva, sizeof(userva));
		if (r) {
			__vm_munmap(userva, 2 * PAGE_SIZE, false);
			break;
		}
		vcpu->run_userva = userva;
		break;
	case GVM_GET_REGS: {
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
		if (!kvm_regs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_regs(vcpu, kvm_regs);
		if (r)
			goto out_free1;
		r = gvmUpdateReturnBuffer(pIrp, 0, kvm_regs, sizeof(struct kvm_regs));
		if (r)
			goto out_free1;
		r = 0;
out_free1:
		kfree(kvm_regs);
		break;
	}
	case GVM_SET_REGS: {
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = memdup_user(argp, sizeof(*kvm_regs));
		if (IS_ERR(kvm_regs)) {
			r = PTR_ERR(kvm_regs);
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_regs(vcpu, kvm_regs);
		kfree(kvm_regs);
		break;
	}
	case GVM_GET_SREGS: {
		kvm_sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!kvm_sregs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, kvm_sregs);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, kvm_sregs, sizeof(struct kvm_sregs));
		if (r)
			goto out;
		r = 0;
		break;
	}
	case GVM_SET_SREGS: {
		kvm_sregs = memdup_user(argp, sizeof(*kvm_sregs));
		if (IS_ERR(kvm_sregs)) {
			r = PTR_ERR(kvm_sregs);
			kvm_sregs = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, kvm_sregs);
		break;
	}
	case GVM_GET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, &mp_state, sizeof(mp_state));
		break;
	}
	case GVM_SET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = -EFAULT;
		if (copy_from_user(&mp_state, argp, sizeof(mp_state)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
		break;
	}
	case GVM_TRANSLATE: {
		struct kvm_translation tr;

		r = -EFAULT;
		if (copy_from_user(&tr, argp, sizeof(tr)))
			goto out;
		r = kvm_arch_vcpu_ioctl_translate(vcpu, &tr);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, &tr, sizeof(tr));
		break;
	}
	case GVM_SET_GUEST_DEBUG: {
		struct kvm_guest_debug dbg;

		r = -EFAULT;
		if (copy_from_user(&dbg, argp, sizeof(dbg)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		break;
	}
	case GVM_GET_FPU: {
		fpu = kzalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
		if (r)
			goto out;
		r = gvmUpdateReturnBuffer(pIrp, 0, fpu, sizeof(struct kvm_fpu));
		break;
	}
	case GVM_SET_FPU: {
		fpu = memdup_user(argp, sizeof(*fpu));
		if (IS_ERR(fpu)) {
			r = PTR_ERR(fpu);
			fpu = NULL;
			goto out;
		}
		r = kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
		break;
	}
	default:
		r = kvm_arch_vcpu_ioctl(devext, pIrp, ioctl);
	}
out:
	kfree(fpu);
	kfree(kvm_sregs);
	return r;
}

static long kvm_vm_ioctl_check_extension_generic(struct kvm *kvm, long arg)
{
	switch (arg) {
#ifdef CONFIG_HAVE_GVM_MSI
	case GVM_CAP_SIGNAL_MSI:
#endif
	case GVM_CAP_IRQ_ROUTING:
		return GVM_MAX_IRQ_ROUTES;
#if GVM_ADDRESS_SPACE_NUM > 1
	case GVM_CAP_MULTI_ADDRESS_SPACE:
		return GVM_ADDRESS_SPACE_NUM;
#endif
	case GVM_CAP_MAX_VCPU_ID:
		return GVM_MAX_VCPU_ID;
	default:
		break;
	}
	return kvm_vm_ioctl_check_extension(kvm, arg);
}

NTSTATUS kvm_vm_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp,
			   unsigned int ioctl)
{
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	struct kvm *kvm = devext->PrivData;
	void __user *argp = (void __user *)pIrp->AssociatedIrp.SystemBuffer;
	int r;

	if (kvm->process != IoGetCurrentProcess())
		return -EIO;
	switch (ioctl) {
	case GVM_CREATE_VCPU:
		r = kvm_vm_ioctl_create_vcpu(pDevObj, pIrp, argp);
		break;
	case GVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region kvm_userspace_mem;

		r = -EFAULT;
		RtlCopyBytes(&kvm_userspace_mem, pIrp->AssociatedIrp.SystemBuffer, sizeof(kvm_userspace_mem));
		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case GVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof(log)))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
	case GVM_KICK_VCPU:
		r = kvm_vm_ioctl_kick_vcpu(pDevObj, pIrp, argp);
		break;
#ifdef CONFIG_HAVE_GVM_MSI
	case GVM_SIGNAL_MSI: {
		struct kvm_msi msi;

		r = -EFAULT;
		if (copy_from_user(&msi, argp, sizeof(msi)))
			goto out;
		r = kvm_send_userspace_msi(kvm, &msi);
		break;
	}
#endif
	case GVM_IRQ_LINE_STATUS: {
		struct kvm_irq_level irq_event;

		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
			goto out;

		r = kvm_vm_ioctl_irq_line(kvm, &irq_event, true);
		if (r)
			goto out;

		if (ioctl == GVM_IRQ_LINE_STATUS) {
			r = gvmUpdateReturnBuffer(pIrp, 0, &irq_event,
				       sizeof(irq_event));
			if (r)
				goto out;
		}

		r = 0;
		break;
	}
	case GVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing routing;
		struct kvm_irq_routing __user *urouting;
		struct kvm_irq_routing_entry *entries = NULL;

		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		if (routing.nr > GVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		if (routing.nr) {
			r = -ENOMEM;
			entries = vmalloc(routing.nr * sizeof(*entries));
			if (!entries)
				goto out;
			r = -EFAULT;
			urouting = argp;
			if (copy_from_user(entries, urouting->entries,
					   routing.nr * sizeof(*entries)))
				goto out_free_irq_routing;
		}
		r = kvm_set_irq_routing(kvm, entries, routing.nr,
					routing.flags);
out_free_irq_routing:
		vfree(entries);
		break;
	}
	case GVM_CHECK_EXTENSION:
		r = kvm_vm_ioctl_check_extension_generic(kvm, *(long *)argp);
		gvmUpdateReturnBuffer(pIrp, 0, &r, sizeof(r));
		r = STATUS_SUCCESS;
		break;
	default:
		r = kvm_arch_vm_ioctl(devext, pIrp, ioctl);
	}
out:
	return r;
}

static int kvm_dev_ioctl_create_vm(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned long arg)
{
	struct kvm *kvm;
	NTSTATUS rc;
	HANDLE handle;
	unsigned int type = arg;

	kvm = kvm_create_vm(type);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);

	rc = gvmCreateVMDevice(&handle, kvm->vm_id, -1, kvm);
	if (NT_SUCCESS(rc))
		gvmUpdateReturnBuffer(pIrp, 0, &handle, sizeof(handle));
	return rc;
}

NTSTATUS kvm_dev_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp,
			  unsigned int ioctl)
{
	long r = -EINVAL;
	struct gvm_device_extension *devext = pDevObj->DeviceExtension;
	void* pin = pIrp->AssociatedIrp.SystemBuffer;

	switch (ioctl) {
	case GVM_GET_API_VERSION:
		r = GVM_VERSION;
		gvmUpdateReturnBuffer(pIrp, 0, &r, sizeof(r));
		r = STATUS_SUCCESS;
		break;
	case GVM_CREATE_VM:
		r = kvm_dev_ioctl_create_vm(pDevObj, pIrp, 0);
		break;
	case GVM_CHECK_EXTENSION:
		r = kvm_vm_ioctl_check_extension_generic(NULL, *(long *)pin);
		gvmUpdateReturnBuffer(pIrp, 0, &r, sizeof(r));
		r = STATUS_SUCCESS;
		break;
	case GVM_GET_VCPU_MMAP_SIZE:
		long mmap_size = 2 * PAGE_SIZE;
		r = gvmUpdateReturnBuffer(pIrp, 0, &mmap_size, sizeof(mmap_size));
		break;
	default:
		return kvm_arch_dev_ioctl(devext, pIrp, ioctl);
	}
	return r;
}

static void hardware_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;

	cpumask_set_cpu(cpu, cpus_hardware_enabled);

	r = kvm_arch_hardware_enable();

	if (r) {
		cpumask_clear_cpu(cpu, cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		pr_info("kvm: enabling virtualization on CPU%d failed\n", cpu);
	}

	return;
}

static int kvm_starting_cpu(unsigned int cpu)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count)
		hardware_enable_nolock(NULL);
	raw_spin_unlock(&kvm_count_lock);
	return 0;
}

static void hardware_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;
	cpumask_clear_cpu(cpu, cpus_hardware_enabled);
	kvm_arch_hardware_disable();
}

static int kvm_dying_cpu(unsigned int cpu)
{
	raw_spin_lock(&kvm_count_lock);
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	raw_spin_unlock(&kvm_count_lock);
	return 0;
}

static void hardware_disable_all_nolock(void)
{
	BUG_ON(!kvm_usage_count);

	kvm_usage_count--;
	if (!kvm_usage_count)
		smp_call_function_many(cpu_online_mask, hardware_disable_nolock, NULL, 1);
}

static void hardware_disable_all(void)
{
	raw_spin_lock(&kvm_count_lock);
	hardware_disable_all_nolock();
	raw_spin_unlock(&kvm_count_lock);
}

static int hardware_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&kvm_count_lock);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		atomic_set(&hardware_enable_failed, 0);
		smp_call_function_many(cpu_online_mask, hardware_enable_nolock, NULL, 1);
		if (atomic_read(&hardware_enable_failed)) {
			hardware_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&kvm_count_lock);

	return r;
}

static void kvm_io_bus_destroy(struct kvm_io_bus *bus)
{
	int i;

	for (i = 0; i < bus->dev_count; i++) {
		struct kvm_io_device *pos = bus->range[i].dev;

		kvm_iodevice_destructor(pos);
	}
	kfree(bus);
}

static inline int kvm_io_bus_cmp(const struct kvm_io_range *r1,
				 const struct kvm_io_range *r2)
{
	gpa_t addr1 = r1->addr;
	gpa_t addr2 = r2->addr;

	if (addr1 < addr2)
		return -1;

	/* If r2->len == 0, match the exact address.  If r2->len != 0,
	 * accept any overlapping write.  Any order is acceptable for
	 * overlapping ranges, because kvm_io_bus_get_first_dev ensures
	 * we process all of them.
	 */
	if (r2->len) {
		addr1 += r1->len;
		addr2 += r2->len;
	}

	if (addr1 > addr2)
		return 1;

	return 0;
}

static int kvm_io_bus_sort_cmp(const void *p1, const void *p2)
{
	return kvm_io_bus_cmp(p1, p2);
}

static int kvm_io_bus_insert_dev(struct kvm_io_bus *bus, struct kvm_io_device *dev,
			  gpa_t addr, int len)
{
	bus->range[bus->dev_count++] = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
		.dev = dev,
	};

	sort(bus->range, bus->dev_count, sizeof(struct kvm_io_range),
		kvm_io_bus_sort_cmp, NULL);

	return 0;
}

static int kvm_io_bus_get_first_dev(struct kvm_io_bus *bus,
			     gpa_t addr, int len)
{
	struct kvm_io_range *range, key;
	int off;

	key = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	range = bsearch(&key, bus->range, bus->dev_count,
			sizeof(struct kvm_io_range), kvm_io_bus_sort_cmp);
	if (range == NULL)
		return -ENOENT;

	off = range - bus->range;

	while (off > 0 && kvm_io_bus_cmp(&key, &bus->range[off-1]) == 0)
		off--;

	return off;
}

static int __kvm_io_bus_write(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			      struct kvm_io_range *range, const void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_write(vcpu, bus->range[idx].dev, range->addr,
					range->len, val))
			return idx;
		idx++;
	}

	return -EOPNOTSUPP;
}

/* kvm_io_bus_write - called under kvm->slots_lock */
int kvm_io_bus_write(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	bus = vcpu->kvm->buses[bus_idx];
	r = __kvm_io_bus_write(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}

/* kvm_io_bus_write_cookie - called under kvm->slots_lock */
int kvm_io_bus_write_cookie(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx,
			    gpa_t addr, int len, const void *val, long cookie)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	bus = vcpu->kvm->buses[bus_idx];

	/* First try the device referenced by cookie. */
	if ((cookie >= 0) && (cookie < bus->dev_count) &&
	    (kvm_io_bus_cmp(&range, &bus->range[cookie]) == 0))
		if (!kvm_iodevice_write(vcpu, bus->range[cookie].dev, addr, len,
					val))
			return cookie;

	/*
	 * cookie contained garbage; fall back to search and return the
	 * correct cookie value.
	 */
	return __kvm_io_bus_write(vcpu, bus, &range, val);
}

static int __kvm_io_bus_read(struct kvm_vcpu *vcpu, struct kvm_io_bus *bus,
			     struct kvm_io_range *range, void *val)
{
	int idx;

	idx = kvm_io_bus_get_first_dev(bus, range->addr, range->len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_cmp(range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_read(vcpu, bus->range[idx].dev, range->addr,
				       range->len, val))
			return idx;
		idx++;
	}

	return -EOPNOTSUPP;
}

/* kvm_io_bus_read - called under kvm->slots_lock */
int kvm_io_bus_read(struct kvm_vcpu *vcpu, enum kvm_bus bus_idx, gpa_t addr,
		    int len, void *val)
{
	struct kvm_io_bus *bus;
	struct kvm_io_range range;
	int r;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(vcpu->kvm->buses[bus_idx], &vcpu->kvm->srcu);
	bus = vcpu->kvm->buses[bus_idx];
	r = __kvm_io_bus_read(vcpu, bus, &range, val);
	return r < 0 ? r : 0;
}


/* Caller must hold slots_lock. */
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
			    int len, struct kvm_io_device *dev)
{
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm->buses[bus_idx];
	if (bus->dev_count > NR_IOBUS_DEVS - 1)
		return -ENOSPC;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count + 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;
	memcpy(new_bus, bus, sizeof(*bus) + (bus->dev_count *
	       sizeof(struct kvm_io_range)));
	kvm_io_bus_insert_dev(new_bus, dev, addr, len);
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);

	return 0;
}

/* Caller must hold slots_lock. */
int kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			      struct kvm_io_device *dev)
{
	int i, r;
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm->buses[bus_idx];
	r = -ENOENT;
	for (i = 0; i < bus->dev_count; i++)
		if (bus->range[i].dev == dev) {
			r = 0;
			break;
		}

	if (r)
		return r;

	new_bus = kmalloc(sizeof(*bus) + ((bus->dev_count - 1) *
			  sizeof(struct kvm_io_range)), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;

	memcpy(new_bus, bus, sizeof(*bus) + i * sizeof(struct kvm_io_range));
	new_bus->dev_count--;
	memcpy(new_bus->range + i, bus->range + i + 1,
	       (new_bus->dev_count - i) * sizeof(struct kvm_io_range));

	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);
	return r;
}

struct kvm_io_device *kvm_io_bus_get_dev(struct kvm *kvm, enum kvm_bus bus_idx,
					 gpa_t addr)
{
	struct kvm_io_bus *bus;
	int dev_idx, srcu_idx;
	struct kvm_io_device *iodev = NULL;

	srcu_idx = srcu_read_lock(&kvm->srcu);

	bus = srcu_dereference(kvm->buses[bus_idx], &kvm->srcu);
	bus = kvm->buses[bus_idx];

	dev_idx = kvm_io_bus_get_first_dev(bus, addr, 1);
	if (dev_idx < 0)
		goto out_unlock;

	iodev = bus->range[dev_idx].dev;

out_unlock:
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return iodev;
}

/*
 * The following two functions are kept here so that they
 * could be used once hooking driver with Windows Power State
 * chage.
 */
int kvm_suspend(void)
{
	if (kvm_usage_count)
		smp_call_function_many(cpu_online_mask,
				hardware_disable_nolock, NULL, 1);
	return 0;
}

void kvm_resume(void)
{
	if (kvm_usage_count)
		smp_call_function_many(cpu_online_mask,
				hardware_enable_nolock, NULL, 1);
}

int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align)
{
	int r;

	r = kvm_arch_init(opaque);
	if (r)
		goto out_fail;

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}

	r = kvm_arch_hardware_setup();
	if (r < 0)
		goto out_free_0a;

	kvm_arch_check_processor_compat(&r);
	if (r < 0)
		goto out_free_1;

	return 0;

out_free_1:
	kvm_arch_hardware_unsetup();
out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);
out_free_0:
	kvm_arch_exit();
out_fail:
	return r;
}

void kvm_exit(void)
{
	smp_call_function_many(cpu_online_mask,
			hardware_disable_nolock, NULL, 1);
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	free_cpumask_var(cpus_hardware_enabled);
}
