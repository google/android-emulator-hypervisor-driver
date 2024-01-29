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
#include <ntstrsafe.h>
#include <aehd_types.h>
#include <ntkrutils.h>

#define AEHD_DEVICE_TOP 0
#define AEHD_DEVICE_VM 1
#define AEHD_DEVICE_VCPU 2
struct aehd_device_extension {
	UINT32 DevType;
	PVOID PrivData;
};

extern PVOID pZeroPage;

extern int aehdUpdateReturnBuffer(PIRP pIrp, u32 start, void *src, u32 size);
extern int aehdCopyInputBuffer(PIRP pIrp, u32 start, void* dst, u32 size);
extern void* aehdMemdupUser(PIRP pIrp, u32 start, u32 size);

extern void aehdWaitSuspend(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2) ;
extern long kvm_dev_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vm_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vcpu_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vcpu_fast_ioctl_run(PDEVICE_OBJECT pDevObj);
extern NTSTATUS aehdCreateVMDevice(PHANDLE pHandle, UINT32 vmNumber, INT32 vcpuNumber,
	PVOID PrivData);
extern NTSTATUS aehdDeleteVMDevice(PDEVICE_OBJECT pDevObj, UINT32 vmNumber, INT32 vcpuNumber);
