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
#include <gvm_types.h>
#include <ntkrutils.h>

#define GVM_DEVICE_TOP 0
#define GVM_DEVICE_VM 1
#define GVM_DEVICE_VCPU 2
struct gvm_device_extension {
	UINT32 DevType;
	PVOID PrivData;
};

extern PVOID pZeroPage;

extern int gvmUpdateReturnBuffer(PIRP pIrp, size_t start, void *src, size_t size);
extern void gvmWaitSuspend(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2) ;
extern long kvm_dev_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vm_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vcpu_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp, unsigned int ioctl);
extern long kvm_vcpu_fast_ioctl_run(PDEVICE_OBJECT pDevObj);
extern NTSTATUS gvmCreateVMDevice(PHANDLE pHandle, UINT32 vmNumber, INT32 vcpuNumber,
	PVOID PrivData);
extern NTSTATUS gvmDeleteVMDevice(PDEVICE_OBJECT pDevObj, UINT32 vmNumber, INT32 vcpuNumber);
