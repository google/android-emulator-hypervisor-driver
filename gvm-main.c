/*
 * Copyright 2019 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <ntddk.h>
#include <gvm-main.h>
#include <ntkrutils.h>
#include <linux/kvm_host.h>

#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))

struct cpuinfo_x86 boot_cpu_data;

/* Device Name */
#define GVM_DEVICE_NAME L"\\Device\\gvm"
#define GVM_DOS_DEVICE_NAME L"\\DosDevices\\gvm"
#define POWER_CALL_BACK_NAME L"\\Callback\\PowerState"

static PCALLBACK_OBJECT power_callback;
static PVOID power_callback_handle;
static int suspend;
static atomic_t suspend_wait;
char CPUString[13];

DRIVER_INITIALIZE DriverEntry;

PDRIVER_OBJECT gpDrvObj;

PVOID pZeroPage = NULL;

extern int vmx_init(void);
extern void vmx_exit(void);
extern int svm_init(void);
extern void svm_exit(void);
extern int kvm_suspend(void);
extern void kvm_resume(void);

int gvmUpdateReturnBuffer(PIRP pIrp, u32 start, void *src, u32 size)
{
	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	unsigned char *pBuff = pIrp->AssociatedIrp.SystemBuffer;
	u32 buffSize = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

	if (((u64)start + (u64)size) > buffSize)
		return -E2BIG;

	RtlCopyBytes(pBuff + start, src, size);
	pIrp->IoStatus.Information = start + size;
	return 0;
}

VOID NTAPI gvmWaitSuspend(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2) 
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	atomic_inc(&suspend_wait);

	while (suspend)
		_mm_pause();

	atomic_dec(&suspend_wait);
}

VOID gvmDriverUnload(PDRIVER_OBJECT pDrvObj)
{
	//XXX: Clean up other devices?
	PDEVICE_OBJECT pDevObj = pDrvObj->DeviceObject;
	UNICODE_STRING DosDeviceName;
	unsigned int eax = 0;

	if (power_callback_handle)
		ExUnregisterCallback(power_callback_handle);
	if (power_callback)
		ObDereferenceObject(power_callback);

	RtlInitUnicodeString(&DosDeviceName, GVM_DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(pDevObj);

	RtlZeroBytes(CPUString, 13);
	cpuid(0, &eax,
	      (unsigned int *)&CPUString[0],
	      (unsigned int *)&CPUString[8],
	      (unsigned int *)&CPUString[4]);
	if (strcmp("GenuineIntel", CPUString) == 0)
		vmx_exit();
	else if (strcmp("AuthenticAMD", CPUString) == 0)
		svm_exit();

	ExFreePoolWithTag(pZeroPage, GVM_POOL_TAG);
	NtKrUtilsExit();
}

NTSTATUS kvm_vcpu_release(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS kvm_vm_release(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS gvmDeviceClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS rc = STATUS_INVALID_PARAMETER;
	struct gvm_device_extension *pDevExt;

	DbgPrint("GVM device close\n");

	pDevExt = pDevObj->DeviceExtension;
	switch (pDevExt->DevType) {
	case GVM_DEVICE_TOP:
		rc = STATUS_SUCCESS;
		break;
	case GVM_DEVICE_VM:
		rc = kvm_vm_release(pDevObj, pIrp);
		break;
	case GVM_DEVICE_VCPU:
		rc = kvm_vcpu_release(pDevObj, pIrp);
		break;
	default:
		DbgPrint("gvm Device Close with incorrect device type!\n");
	}

	if (pDevExt->DevType != GVM_DEVICE_TOP)
		IoDeleteDevice(pDevObj);

	// Completing the device control
	pIrp->IoStatus.Status = rc;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return rc;
}

NTSTATUS gvmDeviceCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("GVM device open\n");
	UNREFERENCED_PARAMETER(pDevObj);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS gvmCreateVMDevice(PHANDLE pHandle,
			   UINT32 vmNumber, INT32 vcpuNumber, PVOID PrivData)
{
	UNICODE_STRING deviceName;
	WCHAR wDeviceName[64] = { 0 };
	PDEVICE_OBJECT pDevObj = NULL;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS rc;
	HANDLE handle;
	IO_STATUS_BLOCK ioStatBlock;
	struct gvm_device_extension *pDevExt;

	RtlInitEmptyUnicodeString(&deviceName, wDeviceName, 64);

	if (vcpuNumber == -1)
		RtlUnicodeStringPrintf(&deviceName,
				       L"\\Device\\gvm_vm%d", vmNumber);
	else if(vcpuNumber >= 0 && vcpuNumber <= 128 )
		RtlUnicodeStringPrintf(&deviceName,
				       L"\\Device\\gvm_vm%d_vcpu%d",
				       vmNumber,
				       vcpuNumber);

	rc = IoCreateDevice(gpDrvObj,
		            sizeof(struct gvm_device_extension),
			    &deviceName,
			    FILE_DEVICE_GVM,
			    FILE_DEVICE_SECURE_OPEN,
			    FALSE,
			    &pDevObj);
	if (!NT_SUCCESS(rc))
		return rc;

	pDevExt = pDevObj->DeviceExtension;
	if (vcpuNumber == -1)
		pDevExt->DevType = GVM_DEVICE_VM;
	else
		pDevExt->DevType = GVM_DEVICE_VCPU;
	pDevExt->PrivData = PrivData;

	ClearFlag(pDevObj->Flags, DO_DEVICE_INITIALIZING);

	InitializeObjectAttributes(&objAttr, &deviceName, 0, NULL, NULL);
	
	rc = ZwCreateFile(&handle,
			  GENERIC_ALL,
			  &objAttr,
			  &ioStatBlock,
			  NULL,
			  FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ | FILE_SHARE_WRITE,
			  FILE_OPEN,
			  FILE_NON_DIRECTORY_FILE,
			  0, 0);
	if (NT_SUCCESS(rc))
		*pHandle = handle;

	return rc;
}

NTSTATUS gvmDeleteVMDevice(PDEVICE_OBJECT pDevObj,
			   UINT32 vmNumber, INT32 vcpuNumber)
{
	UNICODE_STRING deviceName;
	WCHAR wDeviceName[32] = { 0 };
	PFILE_OBJECT pFileObj = NULL;
	NTSTATUS rc;

	// If Device Object is already specified, simple delete it
	if (pDevObj)
		IoDeleteDevice(pDevObj);

	// We need to locate the device object first
	RtlInitEmptyUnicodeString(&deviceName, wDeviceName, 32);

	if (vcpuNumber == -1)
		RtlUnicodeStringPrintf(&deviceName,
				       L"\\Device\\gvm_vm%d", vmNumber);
	else if (vcpuNumber >= 0 && vcpuNumber <= 128)
		RtlUnicodeStringPrintf(&deviceName,
				       L"\\Device\\gvm_vm%d_vcpu%d",
				       vmNumber,
				       vcpuNumber);

	rc = IoGetDeviceObjectPointer(&deviceName,
				      FILE_ALL_ACCESS,
				      &pFileObj,
				      &pDevObj);
	ObDereferenceObject(pFileObj);
	if (!NT_SUCCESS(rc))
		goto out;

	IoDeleteDevice(pDevObj);
out:
	return rc;
}

static NTSTATUS gvmTranslateErrorcode(int r)
{
	switch (r) {
	case -EINVAL:
		return STATUS_INVALID_PARAMETER;
	case -EAGAIN:
		return STATUS_RETRY;
	case -E2BIG:
		return STATUS_BUFFER_OVERFLOW;
	case -EFAULT:
		return STATUS_INTERNAL_ERROR;
	default:
		break;
	}

	return r;
}

BOOLEAN gvmFastIoDeviceControl(
		PFILE_OBJECT notused1,
		BOOLEAN notused2,
		PVOID notused3,
		ULONG notused4,
		PVOID notused5,
		ULONG notused6,
		ULONG ioctl,
		PIO_STATUS_BLOCK pIoStatus,
		PDEVICE_OBJECT pDevObj)
{
	struct gvm_device_extension *pDevExt;
	NTSTATUS rc = STATUS_INVALID_PARAMETER;

	/* Fast IO Device Control is only for run call */
	if (ioctl != GVM_RUN)
		return FALSE;

	pDevExt = pDevObj->DeviceExtension;
	if (pDevExt->DevType != GVM_DEVICE_VCPU)
		return FALSE;

	rc = kvm_vcpu_fast_ioctl_run(pDevObj);

	pIoStatus->Status = gvmTranslateErrorcode(rc);
	return TRUE;
}

NTSTATUS gvmDeviceControl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS rc = STATUS_INVALID_PARAMETER;
	PIO_STACK_LOCATION pIoStackLocation;
	ULONG ioctl;
	size_t arg;
	struct gvm_device_extension *pDevExt;

	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	NT_ASSERT(pIoStackLocation != NULL);

	ioctl = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	arg = (size_t)pIrp->AssociatedIrp.SystemBuffer;
	
	pDevExt = pDevObj->DeviceExtension;
	switch (pDevExt->DevType) {
	case GVM_DEVICE_TOP:
		rc = kvm_dev_ioctl(pDevObj, pIrp, ioctl);
		break;
	case GVM_DEVICE_VM:
		rc = kvm_vm_ioctl(pDevObj, pIrp, ioctl);
		break;
	case GVM_DEVICE_VCPU:
		rc = kvm_vcpu_ioctl(pDevObj, pIrp, ioctl);
		break;
	default:
		DbgPrint("gvm Device Control with incorrect device type!\n");
	}

	rc = gvmTranslateErrorcode(rc);

	// Completing the device control
	pIrp->IoStatus.Status = rc;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return rc;
}

static void gvmPowerCallback(void *notused, void *arg1, void *arg2)
{
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	int i, wait;

	if (arg1 != (PVOID) PO_CB_SYSTEM_STATE_LOCK)
		return;

	if (arg2 == (PVOID) 0) {
		// About to enter suspend mode
		suspend = 1;
		wait = 0;
#define LIST_ENTRY_TYPE_INFO struct kvm
		list_for_each_entry(kvm, &vm_list, vm_list) {
			kvm_for_each_vcpu(i, vcpu, kvm) {
				if (KeInsertQueueApc(&vcpu->apc, 0, 0, 0))
					wait++;
			}
		}
#undef LIST_ENTRY_TYPE_INFO
		// Wait APC preempted vcpu threads
		while (wait != suspend_wait)
			_mm_pause();
		kvm_suspend();
	} else if (arg2 == (PVOID)1) {
		// Resume from suspend mode
		kvm_resume();
		suspend = 0;
	}
}

static FAST_IO_DISPATCH fastIoDispatch;
NTSTATUS _stdcall DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	UNICODE_STRING DeviceName;
	UNICODE_STRING DosDeviceName;
	UNICODE_STRING PowerCallbackName;;
	OBJECT_ATTRIBUTES PowerCallbackAttr;
	PDEVICE_OBJECT pDevObj = NULL;
	struct gvm_device_extension *pDevExt;
	NTSTATUS rc;
	int r;

	rc = NtKrUtilsInit();
	if (!NT_SUCCESS(rc))
		return rc;

	// Allocate and Initialize a zero page
	pZeroPage = ExAllocatePoolWithTag(NonPagedPool,
					  PAGE_SIZE, GVM_POOL_TAG);
	if (!pZeroPage)
		return STATUS_NO_MEMORY;
	RtlZeroBytes(pZeroPage, PAGE_SIZE);

	if (is_Intel())
		r = vmx_init();
	else if (is_AMD())
		r = svm_init();
	else {
		DbgPrint("Processor %s is not supported\n", CPUString);
		r = STATUS_NOT_SUPPORTED;
	}
	if (r)
		return r;

	gpDrvObj = pDrvObj;

	RtlInitUnicodeString(&DeviceName, GVM_DEVICE_NAME);

	rc = IoCreateDevice(pDrvObj,
			    sizeof(struct gvm_device_extension),
			    &DeviceName,
			    FILE_DEVICE_GVM,
			    FILE_DEVICE_SECURE_OPEN,
			    FALSE,
			    &pDevObj);

	if (!NT_SUCCESS(rc))
		goto out_free1;

	pDevExt = pDevObj->DeviceExtension;
	pDevExt->DevType = GVM_DEVICE_TOP;

	pDrvObj->DriverUnload = gvmDriverUnload;
	pDrvObj->MajorFunction[IRP_MJ_CREATE] = gvmDeviceCreate;
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = gvmDeviceClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = gvmDeviceControl;

	/* Windows Fast Io Device Control */
	RtlZeroMemory(&fastIoDispatch, sizeof(FAST_IO_DISPATCH));
	fastIoDispatch.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
	fastIoDispatch.FastIoDeviceControl = gvmFastIoDeviceControl;
	pDrvObj->FastIoDispatch = &fastIoDispatch;

	/* Register callback for system sleep transitions.
	 * According to OSR online document, the other way available
	 * is to convert the driver to be PNP compliant.
	 */
	RtlInitUnicodeString(&PowerCallbackName, POWER_CALL_BACK_NAME);
	InitializeObjectAttributes(&PowerCallbackAttr,
				   &PowerCallbackName, 0, NULL, NULL);
	rc = ExCreateCallback(&power_callback, &PowerCallbackAttr,
			      true, true);
	if (NT_SUCCESS(rc))
		power_callback_handle = ExRegisterCallback(power_callback,
					   gvmPowerCallback,
					   NULL);

	RtlInitUnicodeString(&DosDeviceName, GVM_DOS_DEVICE_NAME);

	rc = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
	if (!NT_SUCCESS(rc))
		goto out_free2;

	return STATUS_SUCCESS;

out_free2:
	IoDeleteDevice(pDevObj);
out_free1:
	return rc;
	// Great Project... Please accept my merge request!...
}
