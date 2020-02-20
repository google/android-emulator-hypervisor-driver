; Copyright 2019 Google LLC

; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; version 2 as published by the Free Software Foundation.

; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU General Public License for more details.

; low-level assembly code for gvm as there is no inline assembly support
; from microsoft c++ compiler.
include <__asm.inc>

KeBugCheck PROTO STDCALL :DWORD
public vmx_return
        .data
vmx_return qword offset ret_from_nonroot

        .code
__spin_lock proc
		xor edx, edx
		inc edx
		jmp __spin_lock_try
__spin_lock_retry:
		pause
__spin_lock_try:
		xor eax, eax
		lock cmpxchg [rcx], edx
		jnz __spin_lock_retry
		ret
__spin_lock endp

read_flags proc
		pushfq
		pop rax
		ret
read_flags endp

__fninit proc
		fninit
		ret
__fninit endp

__fnstsw proc
		fnstsw word ptr[rcx]
		ret
__fnstsw endp

__fnstcw proc
		fnstcw word ptr[rcx]
		ret
__fnstcw endp

__fwait proc
		fwait
		ret
__fwait endp

__clts proc
		clts
		ret
__clts endp

__bswap64 proc
		mov rax, qword ptr[rcx]
		bswap rax
		mov qword ptr[rcx], rax
		ret
__bswap64 endp

__bswap32 proc
		mov eax, dword ptr[rcx]
		bswap eax
		mov dword ptr[rcx], eax
		ret
__bswap32 endp

align 16
__int2 proc
		int 2
		ret
__int2 endp

__divq proc
		mov rax, rcx
		div r8
		ret
__divq endp

xchg8 proc
		mov al, dl
		lock xchg [rcx], al
		ret
xchg8 endp

xchg16 proc
		mov ax, dx
		lock xchg [rcx], ax
		ret
xchg16 endp

cmpxchg8 proc
		mov al, dl
		lock cmpxchg [rcx], r8b
		ret
cmpxchg8 endp

cmpxchg16 proc
		mov ax, dx
		lock cmpxchg [rcx], r8w
		ret
cmpxchg16 endp

load_TR_desc proc
	mov rcx, 40h
	ltr cx
	ret
load_TR_desc endp

gvm_read_ldt proc
	sldt ax
	ret
gvm_read_ldt endp

gvm_load_ldt proc
	lldt cx
	ret
gvm_load_ldt endp

gvm_read_tr proc
	str ax
	ret
gvm_read_tr endp

gvm_load_tr proc
	ltr cx
	ret
gvm_load_tr endp

load_ss_segment proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	mov ss, cx
	
	mov rsp, rbp
	pop rbp
	ret
load_ss_segment endp

load_ds_segment proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	mov ds, cx
	
	mov rsp, rbp
	pop rbp
	ret
load_ds_segment endp

load_es_segment proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	mov es, cx
	
	mov rsp, rbp
	pop rbp
	ret
load_es_segment endp

load_fs_segment proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	mov fs, cx
	
	mov rsp, rbp
	pop rbp
	ret
load_fs_segment endp

load_gs_segment proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	mov gs, cx
	
	mov rsp, rbp
	pop rbp
	ret
load_gs_segment endp

load_gs_index proc frame
	push rbp
	.pushreg rbp
	mov rbp, rsp
	.setframe rbp, 0
	.endprolog

	swapgs
	mov gs, cx
	swapgs

	mov rsp, rbp;
	pop rbp;
	ret
load_gs_index endp

save_cs_segment proc
	mov ax, cs
	ret
save_cs_segment endp

save_ss_segment proc
	mov ax, ss
	ret
save_ss_segment endp

save_ds_segment proc
	mov ax, ds
	ret
save_ds_segment endp

save_es_segment proc
	mov ax, es
	ret
save_es_segment endp

save_fs_segment proc
	mov ax, fs
	ret
save_fs_segment endp

save_gs_segment proc
	mov ax, gs
	ret
save_gs_segment endp

__asm_vmx_vcpu_run proc
	;save abi non-volatile registers
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi
	push rbx
	;save host flags
	pushfq
	;refer to KVM
	push rbp
	push rcx
	push rcx
	cmp rsp, qword ptr VMX_TO_RSP[rcx]
	je skip_save_rsp
	mov qword ptr VMX_TO_RSP[rcx], rsp
	mov rdx, 6c14h
	vmwrite rdx, rsp
skip_save_rsp:
	mov rax, qword ptr VMX_TO_CR2[rcx]
	mov rdx, cr2
	cmp rax, rdx
	je skip_load_cr2
	mov cr2, rax
skip_load_cr2:
	cmp byte ptr VMX_TO_LAUNCHED[rcx], 0h
	mov rax, qword ptr VMX_TO_RAX[rcx] 
	mov rbx, qword ptr VMX_TO_RBX[rcx] 
	mov rdx, qword ptr VMX_TO_RDX[rcx] 
	mov rsi, qword ptr VMX_TO_RSI[rcx] 
	mov rdi, qword ptr VMX_TO_RDI[rcx] 
	mov rbp, qword ptr VMX_TO_RBP[rcx] 
	mov r8, qword ptr VMX_TO_R8[rcx] 
	mov r9, qword ptr VMX_TO_R9[rcx] 
	mov r10, qword ptr VMX_TO_R10[rcx] 
	mov r11, qword ptr VMX_TO_R11[rcx] 
	mov r12, qword ptr VMX_TO_R12[rcx] 
	mov r13, qword ptr VMX_TO_R13[rcx] 
	mov r14, qword ptr VMX_TO_R14[rcx] 
	mov r15, qword ptr VMX_TO_R15[rcx] 
	mov rcx, qword ptr VMX_TO_RCX[rcx] 
	jne go_resume
	vmlaunch
	jmp ret_from_nonroot
go_resume:
	vmresume
ret_from_nonroot::
	mov qword ptr 8h[rsp], rcx
	pop rcx
	mov qword ptr VMX_TO_RAX[rcx], rax
	mov qword ptr VMX_TO_RBX[rcx], rbx 
	pop qword ptr VMX_TO_RCX[rcx]
	mov qword ptr VMX_TO_RDX[rcx], rdx 
	mov qword ptr VMX_TO_RSI[rcx], rsi 
	mov qword ptr VMX_TO_RDI[rcx], rdi 
	mov qword ptr VMX_TO_RBP[rcx], rbp 
	mov qword ptr VMX_TO_R8[rcx], r8 
	mov qword ptr VMX_TO_R9[rcx], r9 
	mov qword ptr VMX_TO_R10[rcx], r10 
	mov qword ptr VMX_TO_R11[rcx], r11 
	mov qword ptr VMX_TO_R12[rcx], r12 
	mov qword ptr VMX_TO_R13[rcx], r13 
	mov qword ptr VMX_TO_R14[rcx], r14 
	mov qword ptr VMX_TO_R15[rcx], r15 
	mov rax, cr2
	mov qword ptr VMX_TO_CR2[rcx], rax
	setbe byte ptr VMX_TO_FAIL[rcx]
	pop rbp
	;restore host flags
	popfq
	pop rbx
	pop rsi
	pop rdi
	pop r15
	pop r14
	pop r13
	pop r12
	ret
__asm_vmx_vcpu_run endp

__asm_vmx_handle_external_intr proc
	mov rax, rsp
	and rsp, 0fffffffffffffff0h
	push 18h
	push rax
	pushfq
	push 10h
	call rcx
	ret
__asm_vmx_handle_external_intr endp

;-----mov mmx-------
__asm_save_mm0 proc
	movq [rcx], mm0
	ret
__asm_save_mm0 endp

__asm_save_mm1 proc
	movq [rcx], mm1
	ret
__asm_save_mm1 endp

__asm_save_mm2 proc
	movq [rcx], mm2
	ret
__asm_save_mm2 endp

__asm_save_mm3 proc
	movq [rcx], mm3
	ret
__asm_save_mm3 endp

__asm_save_mm4 proc
	movq [rcx], mm4
	ret
__asm_save_mm4 endp

__asm_save_mm5 proc
	movq [rcx], mm5
	ret
__asm_save_mm5 endp

__asm_save_mm6 proc
	movq [rcx], mm6
	ret
__asm_save_mm6 endp

__asm_save_mm7 proc
	movq [rcx], mm7
	ret
__asm_save_mm7 endp

__asm_store_mm0 proc
	movq mm0, [rcx]
	ret
__asm_store_mm0 endp

__asm_store_mm1 proc
	movq mm1, [rcx]
	ret
__asm_store_mm1 endp

__asm_store_mm2 proc
	movq mm2, [rcx]
	ret
__asm_store_mm2 endp

__asm_store_mm3 proc
	movq mm3, [rcx]
	ret
__asm_store_mm3 endp

__asm_store_mm4 proc
	movq mm4, [rcx]
	ret
__asm_store_mm4 endp

__asm_store_mm5 proc
	movq mm5, [rcx]
	ret
__asm_store_mm5 endp

__asm_store_mm6 proc
	movq mm6, [rcx]
	ret
__asm_store_mm6 endp

__asm_store_mm7 proc
	movq mm7, [rcx]
	ret
__asm_store_mm7 endp

;-----movdqa-------
__asm_save_xmm0 proc
	movdqa xmmword ptr[rcx], xmm0
	ret
__asm_save_xmm0 endp

__asm_store_xmm0 proc
	movdqa xmm0, xmmword ptr[rcx]
	ret
__asm_store_xmm0 endp

__asm_save_xmm1 proc
	movdqa xmmword ptr[rcx], xmm1
	ret
__asm_save_xmm1 endp

__asm_store_xmm1 proc
	movdqa xmm1, xmmword ptr[rcx]
	ret
__asm_store_xmm1 endp

__asm_save_xmm2 proc
	movdqa xmmword ptr[rcx], xmm2
	ret
__asm_save_xmm2 endp

__asm_store_xmm2 proc
	movdqa xmm2, xmmword ptr[rcx]
	ret
__asm_store_xmm2 endp

__asm_save_xmm3 proc
	movdqa xmmword ptr[rcx], xmm3
	ret
__asm_save_xmm3 endp

__asm_store_xmm3 proc
	movdqa xmm3, xmmword ptr[rcx]
	ret
__asm_store_xmm3 endp

__asm_save_xmm4 proc
	movdqa xmmword ptr[rcx], xmm4
	ret
__asm_save_xmm4 endp

__asm_store_xmm4 proc
	movdqa xmm4, xmmword ptr[rcx]
	ret
__asm_store_xmm4 endp

__asm_save_xmm5 proc
	movdqa xmmword ptr[rcx], xmm5
	ret
__asm_save_xmm5 endp

__asm_store_xmm5 proc
	movdqa xmm5, xmmword ptr[rcx]
	ret
__asm_store_xmm5 endp

__asm_save_xmm6 proc
	movdqa xmmword ptr[rcx], xmm6
	ret
__asm_save_xmm6 endp

__asm_store_xmm6 proc
	movdqa xmm6, xmmword ptr[rcx]
	ret
__asm_store_xmm6 endp

__asm_save_xmm7 proc
	movdqa xmmword ptr[rcx], xmm7
	ret
__asm_save_xmm7 endp

__asm_store_xmm7 proc
	movdqa xmm7, xmmword ptr[rcx]
	ret
__asm_store_xmm7 endp

__asm_save_xmm8 proc
	movdqa xmmword ptr[rcx], xmm8
	ret
__asm_save_xmm8 endp

__asm_store_xmm8 proc
	movdqa xmm8, xmmword ptr[rcx]
	ret
__asm_store_xmm8 endp

__asm_save_xmm9 proc
	movdqa xmmword ptr[rcx], xmm9
	ret
__asm_save_xmm9 endp

__asm_store_xmm9 proc
	movdqa xmm9, xmmword ptr[rcx]
	ret
__asm_store_xmm9 endp

__asm_save_xmm10 proc
	movdqa xmmword ptr[rcx], xmm10
	ret
__asm_save_xmm10 endp

__asm_store_xmm10 proc
	movdqa xmm10, xmmword ptr[rcx]
	ret
__asm_store_xmm10 endp

__asm_save_xmm11 proc
	movdqa xmmword ptr[rcx], xmm11
	ret
__asm_save_xmm11 endp

__asm_store_xmm11 proc
	movdqa xmm11, xmmword ptr[rcx]
	ret
__asm_store_xmm11 endp

__asm_save_xmm12 proc
	movdqa xmmword ptr[rcx], xmm12
	ret
__asm_save_xmm12 endp

__asm_store_xmm12 proc
	movdqa xmm12, xmmword ptr[rcx]
	ret
__asm_store_xmm12 endp

__asm_save_xmm13 proc
	movdqa xmmword ptr[rcx], xmm13
	ret
__asm_save_xmm13 endp

__asm_store_xmm13 proc
	movdqa xmm13, xmmword ptr[rcx]
	ret
__asm_store_xmm13 endp

__asm_save_xmm14 proc
	movdqa xmmword ptr[rcx], xmm14
	ret
__asm_save_xmm14 endp

__asm_store_xmm14 proc
	movdqa xmm14, xmmword ptr[rcx]
	ret
__asm_store_xmm14 endp

__asm_save_xmm15 proc
	movdqa xmmword ptr[rcx], xmm15
	ret
__asm_save_xmm15 endp

__asm_store_xmm15 proc
	movdqa xmm15, xmmword ptr[rcx]
	ret
__asm_store_xmm15 endp

;-----Fastop Functions------
; Fastop functions's entry is __asm_fastop.
; Never call underlying functions directly as it is not written following
; normal ABI.
                  public __asm_test_cc
__asm_test_cc      proc frame
			push rbp
			.pushreg rbp
			mov rbp, rsp
			.setframe rbp, 0
			.endprolog

			push rdx
			popfq
			call rcx

			mov rsp, rbp
			pop rbp
			ret
__asm_test_cc      endp

                  public __asm_fastop
__asm_fastop      proc frame
			push rbp
			.pushreg rbp
			mov rbp, rsp
			.setframe rbp, 0
			.endprolog

			push rdi
			mov rdi, rcx
			push rsi
			mov rsi, rdx
			mov rax, qword ptr CXT_TO_DST[r8]
			mov rdx, qword ptr CXT_TO_SRC[r8]
			mov rcx, qword ptr CXT_TO_SRC2[r8]

			; save host eflags
			pushfq
			push qword ptr[rdi]
			popfq
			call rsi
			pushfq
			pop qword ptr[rdi]
			popfq

			mov qword ptr CXT_TO_DST[r8], rax
			mov qword ptr CXT_TO_SRC[r8], rdx
			pop rsi
			pop rdi

			mov rsp, rbp
			pop rbp
			ret
__asm_fastop      endp

                public kvm_fastop_exception
kvm_fastop_exception proc
                xor     esi, esi
                ret
kvm_fastop_exception endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
				  public em_setcc
em_setcc          proc
__seto            proc
                seto    al
                ret
__seto            endp
em_setcc        endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setno           proc
                setno   al
                ret
__setno           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setc            proc
                setb    al
                ret
__setc            endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnc           proc
                setnb   al
                ret
__setnc           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setz            proc
                setz    al
                ret
__setz            endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnz           proc
                setnz   al
                ret
__setnz           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setbe           proc
                setbe   al
                ret
__setbe           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnbe          proc
                setnbe  al
                ret
__setnbe          endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__sets            proc
                sets    al
                ret
__sets            endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setns           proc
                setns   al
                ret
__setns           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setp            proc
                setp    al
                ret
__setp            endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnp           proc
                setnp   al
                ret
__setnp           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setl            proc
                setl    al
                ret
__setl            endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnl           proc
                setnl   al
                ret
__setnl           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setle           proc
                setle   al
                ret
__setle           endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================
__setnle          proc
                setnle  al
                ret
__setnle          endp

; =============== S U B R O U T I N E =======================================
                  public em_salc
em_salc           proc              
                pushfq
                sbb     al, al
                popfq
                ret
em_salc           endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_add
em_add            proc              
__addb_al_dl      proc                                       
                add     al, dl
                ret
__addb_al_dl      endp
em_add            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__addw_ax_dx      proc
                add     ax, dx
                ret
__addw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__addl_eax_edx    proc
                add     eax, edx
                ret
__addl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__addq_rax_rdx    proc
                add     rax, rdx
                ret
__addq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_or
em_or             proc
__orb_al_dl       proc
                or      al, dl
                ret
__orb_al_dl       endp
em_or             endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__orw_ax_dx       proc
                or      ax, dx
                ret
__orw_ax_dx       endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__orl_eax_edx     proc
                or      eax, edx
                ret
__orl_eax_edx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__orq_rax_rdx     proc
                or      rax, rdx
                ret
__orq_rax_rdx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_adc
em_adc            proc              
__adcb_al_dl      proc
                adc     al, dl
                ret
__adcb_al_dl      endp
em_adc            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__adcw_ax_dx      proc
                adc     ax, dx
                ret
__adcw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__adcl_eax_edx    proc
                adc     eax, edx
                ret
__adcl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__adcq_rax_rdx    proc
                adc     rax, rdx
                ret
__adcq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_sbb
em_sbb            proc              
__sbbb_al_dl      proc
                sbb     al, dl         
                ret
__sbbb_al_dl      endp
em_sbb            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sbbw_ax_dx      proc
                sbb     ax, dx
                ret
__sbbw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sbbl_eax_edx    proc
                sbb     eax, edx
                ret
__sbbl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sbbq_rax_rdx    proc
                sbb     rax, rdx
                ret
__sbbq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_and
em_and            proc              
__andb_al_dl      proc
                and     al, dl
                ret
__andb_al_dl      endp
em_and            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__andw_ax_dx      proc
                and     ax, dx
                ret
__andw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__andl_eax_edx    proc
                and     eax, edx
                ret
__andl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__andq_rax_rdx    proc
                and     rax, rdx
                ret
__andq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_sub
em_sub            proc              
__subb_al_dl      proc
                sub     al, dl         
                ret
__subb_al_dl      endp
em_sub            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__subw_ax_dx      proc
                sub     ax, dx
                ret
__subw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__subl_eax_edx    proc
                sub     eax, edx
                ret
__subl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__subq_rax_rdx    proc
                sub     rax, rdx
                ret
__subq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_xor
em_xor            proc              
__xorb_al_dl      proc
                xor     al, dl         
                ret
__xorb_al_dl      endp
em_xor            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xorw_ax_dx      proc
                xor     ax, dx
                ret
__xorw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xorl_eax_edx    proc
                xor     eax, edx
                ret
__xorl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xorq_rax_rdx    proc
                xor     rax, rdx
                ret
__xorq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_cmp
em_cmp            proc              
__cmpb_al_dl      proc
                cmp     al, dl
                ret
__cmpb_al_dl      endp
em_cmp            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__cmpw_ax_dx      proc
                cmp     ax, dx
                ret
__cmpw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__cmpl_eax_edx    proc
                cmp     eax, edx
                ret
__cmpl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__cmpq_rax_rdx    proc
                cmp     rax, rdx
                ret
__cmpq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_test
em_test           proc              
__testb_al_dl     proc
                test    al, dl         
                ret
__testb_al_dl     endp
em_test           endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__testw_ax_dx     proc
                test    ax, dx
                ret
__testw_ax_dx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__testl_eax_edx   proc
                test    eax, edx
                ret
__testl_eax_edx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__testq_rax_rdx   proc
                test    rax, rdx
                ret
__testq_rax_rdx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_mul_ex
em_mul_ex         proc              
__mul_cl          proc
                mul     cl             
                ret
__mul_cl          endp
em_mul_ex         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__mul_cx          proc
                mul     cx
                ret
__mul_cx          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__mul_ecx         proc
                mul     ecx
                ret
__mul_ecx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__mul_rcx         proc
                mul     rcx
                ret
__mul_rcx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_imul_ex
em_imul_ex        proc              
__imul_cl         proc
                imul    cl             
                ret
__imul_cl         endp
em_imul_ex        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imul_cx         proc
                imul    cx
                ret
__imul_cx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imul_ecx        proc
                imul    ecx
                ret
__imul_ecx        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imul_rcx        proc
                imul    rcx
                ret
__imul_rcx        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_div_ex
em_div_ex         proc              
__div_cl          proc
                div     cl
                ret
__div_cl          endp
em_div_ex         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__div_cx          proc
                div     cx
                ret
__div_cx          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__div_ecx         proc
                div     ecx
                ret
__div_ecx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__div_rcx         proc
                div     rcx
                ret
__div_rcx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_idiv_ex
em_idiv_ex        proc              
__idiv_cl         proc
                idiv    cl             
                ret
__idiv_cl         endp
em_idiv_ex        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__idiv_cx         proc
                idiv    cx
                ret
__idiv_cx         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__idiv_ecx        proc
                idiv    ecx
                ret
__idiv_ecx        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__idiv_rcx        proc
                idiv    rcx
                ret
__idiv_rcx        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_shld
em_shld         proc              
                ret
em_shld         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shldw_ax_dx_cl  proc
                shld    ax, dx, cl
                ret
__shldw_ax_dx_cl  endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shldl_eax_edx_cl proc
                shld    eax, edx, cl
                ret
__shldl_eax_edx_cl endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shldq_rax_rdx_cl proc
                shld    rax, rdx, cl
                ret
__shldq_rax_rdx_cl endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_shrd
em_shrd         proc              
                ret
em_shrd         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrdw_ax_dx_cl  proc
                shrd    ax, dx, cl
                ret
__shrdw_ax_dx_cl  endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrdl_eax_edx_cl proc
                shrd    eax, edx, cl
                ret
__shrdl_eax_edx_cl endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrdq_rax_rdx_cl proc
                shrd    rax, rdx, cl
                ret
__shrdq_rax_rdx_cl endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_imul
em_imul         proc              
                ret
em_imul         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imulw_ax_dx     proc
                imul    ax, dx
                ret
__imulw_ax_dx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imull_eax_edx   proc
                imul    eax, edx
                ret
__imull_eax_edx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__imulq_rax_rdx   proc
                imul    rax, rdx
                ret
__imulq_rax_rdx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_not
em_not            proc              
__notb_al         proc
                not     al             
                ret
__notb_al         endp
em_not            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__notw_ax         proc
                not     ax
                ret
__notw_ax         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__notl_eax        proc
                not     eax
                ret
__notl_eax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__notq_rax        proc
                not     rax
                ret
__notq_rax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_neg
em_neg            proc              
__negb_al         proc
                neg     al             
                ret
__negb_al         endp
em_neg            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__negw_ax         proc
                neg     ax
                ret
__negw_ax         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__negl_eax        proc
                neg     eax
                ret
__negl_eax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__negq_rax        proc
                neg     rax
                ret
__negq_rax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_inc
em_inc            proc              
__incb_al         proc
                inc     al             
                ret
__incb_al         endp
em_inc            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__incw_ax         proc
                inc     ax
                ret
__incw_ax         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__incl_eax        proc
                inc     eax
                ret
__incl_eax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__incq_rax        proc
                inc     rax
                ret
__incq_rax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_dec
em_dec            proc              
__decb_al         proc
                dec     al
                ret
__decb_al         endp
em_dec            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__decw_ax         proc
                dec     ax
                ret
__decw_ax         endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__decl_eax        proc
                dec     eax
                ret
__decl_eax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__decq_rax        proc
                dec     rax
                ret
__decq_rax        endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_rol
em_rol            proc              
__rolb_al_cl      proc
                rol     al, cl         
                ret
__rolb_al_cl      endp
em_rol            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rolw_ax_cl      proc
                rol     ax, cl
                ret
__rolw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__roll_eax_cl     proc
                rol     eax, cl
                ret
__roll_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rolq_rax_cl     proc
                rol     rax, cl
                ret
__rolq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_ror
em_ror            proc              
__rorb_al_cl      proc
                ror     al, cl         
                ret
__rorb_al_cl      endp
em_ror            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rorw_ax_cl      proc
                ror     ax, cl
                ret
__rorw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rorl_eax_cl     proc
                ror     eax, cl
                ret
__rorl_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rorq_rax_cl     proc
                ror     rax, cl
                ret
__rorq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_rcl
em_rcl            proc              
__rclb_al_cl      proc
                rcl     al, cl         
                ret
__rclb_al_cl      endp
em_rcl            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rclw_ax_cl      proc
                rcl     ax, cl
                ret
__rclw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rcll_eax_cl     proc
                rcl     eax, cl
                ret
__rcll_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rclq_rax_cl     proc
                rcl     rax, cl
                ret
__rclq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_rcr
em_rcr            proc              
__rcrb_al_cl      proc
                rcr     al, cl         
                ret
__rcrb_al_cl      endp
em_rcr            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rcrw_ax_cl      proc
                rcr     ax, cl
                ret
__rcrw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rcrl_eax_cl     proc
                rcr     eax, cl
                ret
__rcrl_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__rcrq_rax_cl     proc
                rcr     rax, cl
                ret
__rcrq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_shl
em_shl            proc              
__shlb_al_cl      proc
                shl     al, cl         
                ret
__shlb_al_cl      endp
em_shl            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shlw_ax_cl      proc
                shl     ax, cl
                ret
__shlw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shll_eax_cl     proc
                shl     eax, cl
                ret
__shll_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shlq_rax_cl     proc
                shl     rax, cl
                ret
__shlq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_shr
em_shr            proc              
__shrb_al_cl      proc
                shr     al, cl         
                ret
__shrb_al_cl      endp
em_shr            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrw_ax_cl      proc
                shr     ax, cl
                ret
__shrw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrl_eax_cl     proc
                shr     eax, cl
                ret
__shrl_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__shrq_rax_cl     proc
                shr     rax, cl
                ret
__shrq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_sar
em_sar            proc              
__sarb_al_cl      proc
                sar     al, cl         
                ret
__sarb_al_cl      endp
em_sar            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sarw_ax_cl      proc
                sar     ax, cl
                ret
__sarw_ax_cl      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sarl_eax_cl     proc
                sar     eax, cl
                ret
__sarl_eax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__sarq_rax_cl     proc
                sar     rax, cl
                ret
__sarq_rax_cl     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_bsf
em_bsf          proc              
                ret
em_bsf          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsfw_ax_dx      proc
                bsf     ax, dx
                ret
__bsfw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsfl_eax_edx    proc
                bsf     eax, edx
                ret
__bsfl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsfq_rax_rdx    proc
                bsf     rax, rdx
                ret
__bsfq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_bsr
em_bsr            proc              
                ret
em_bsr            endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsrw_ax_dx      proc
                bsr     ax, dx
                ret
__bsrw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsrl_eax_edx    proc
                bsr     eax, edx
                ret
__bsrl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__bsrq_rax_rdx    proc
                bsr     rax, rdx
                ret
__bsrq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_bt
em_bt           proc              
                ret
em_bt           endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btw_ax_dx       proc
                bt      ax, dx
                ret
__btw_ax_dx       endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btl_eax_edx     proc
                bt      eax, edx
                ret
__btl_eax_edx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btq_rax_rdx     proc
                bt      rax, rdx
                ret
__btq_rax_rdx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_bts
em_bts          proc              
                ret
em_bts          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btsw_ax_dx      proc
                bts     ax, dx
                ret
__btsw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btsl_eax_edx    proc
                bts     eax, edx
                ret
__btsl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btsq_rax_rdx    proc
                bts     rax, rdx
                ret
__btsq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_btr
em_btr          proc              
                ret
em_btr          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btrw_ax_dx      proc
                btr     ax, dx
                ret
__btrw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btrl_eax_edx    proc
                btr     eax, edx
                ret
__btrl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btrq_rax_rdx    proc
                btr     rax, rdx
                ret
__btrq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                public em_btc
em_btc          proc              
                ret
em_btc          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btcw_ax_dx      proc
                btc     ax, dx
                ret
__btcw_ax_dx      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btcl_eax_edx    proc
                btc     eax, edx
                ret
__btcl_eax_edx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__btcq_rax_rdx    proc
                btc     rax, rdx
                ret
__btcq_rax_rdx    endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_xadd
em_xadd           proc              
__xaddb_al_dl     proc
                xadd    al, dl         
                ret
__xaddb_al_dl     endp
em_xadd           endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xaddw_ax_dx     proc
                xadd    ax, dx
                ret
__xaddw_ax_dx     endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xaddl_eax_edx   proc
                xadd    eax, edx
                ret
__xaddl_eax_edx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__xaddq_rax_rdx   proc
                xadd    rax, rdx
                ret
__xaddq_rax_rdx   endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
                  public em_cmp_r
em_cmp_r          proc              
__cmpb_dl_al      proc
                cmp     dl, al
                ret
__cmpb_dl_al      endp
em_cmp_r          endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__cmpw_dx_ax      proc
                cmp     dx, ax
                ret
__cmpw_dx_ax      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================
__cmpl_edx_eax    proc
                cmp     edx, eax
                ret
__cmpl_edx_eax    endp

; ---------------------------------------------------------------------------
                align 8
; =============== S U B R O U T I N E =======================================
__cmpq_rdx_rax    proc
                cmp     rdx, rax
                ret
__cmpq_rdx_rax    endp

__int12 proc
        int 12h
        ret
__int12 endp

__read_dr0 proc
	mov rax, dr0
	ret
__read_dr0 endp

__read_dr1 proc
	mov rax, dr1
	ret
__read_dr1 endp

__read_dr2 proc
	mov rax, dr2
	ret
__read_dr2 endp

__read_dr3 proc
	mov rax, dr3
	ret
__read_dr3 endp

__read_dr6 proc
	mov rax, dr6
	ret
__read_dr6 endp

__read_dr7 proc
	mov rax, dr7
	ret
__read_dr7 endp

__write_dr0 proc
	mov dr0, rcx
	ret
__write_dr0 endp

__write_dr1 proc
	mov dr1, rcx
	ret
__write_dr1 endp

__write_dr2 proc
	mov dr2, rcx
	ret
__write_dr2 endp

__write_dr3 proc
	mov dr3, rcx
	ret
__write_dr3 endp

__write_dr6 proc
	mov dr6, rcx
	ret
__write_dr6 endp

__write_dr7 proc
	mov dr7, rcx
	ret
__write_dr7 endp

__asm_invvpid proc
	invvpid rcx, oword ptr[rdx]
	ja invvpid_success
	mov rcx, 00020001h
	call KeBugCheck
invvpid_success:
	ret
__asm_invvpid endp

__asm_invept proc
	invept rcx, oword ptr[rdx]
	ja invept_success
	mov rcx, 00020001h
	call KeBugCheck
invept_success:
	ret
__asm_invept endp

__asm_svm_vcpu_run proc
	;save abi non-volatile ergisters
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi
	push rbx
	;refer to KVM svm.c
	mov rax, rcx
	push rbp
	mov rbx, qword ptr SVM_TO_RBX[rax]
	mov rcx, qword ptr SVM_TO_RCX[rax]
	mov rdx, qword ptr SVM_TO_RDX[rax]
	mov rsi, qword ptr SVM_TO_RSI[rax]
	mov rdi, qword ptr SVM_TO_RDI[rax]
	mov rbp, qword ptr SVM_TO_RBP[rax]
	mov r8, qword ptr SVM_TO_R8[rax]
	mov r9, qword ptr SVM_TO_R9[rax]
	mov r10, qword ptr SVM_TO_R10[rax]
	mov r11, qword ptr SVM_TO_R11[rax]
	mov r12, qword ptr SVM_TO_R12[rax]
	mov r13, qword ptr SVM_TO_R13[rax]
	mov r14, qword ptr SVM_TO_R14[rax]
	mov r15, qword ptr SVM_TO_R15[rax]
	;Enter guest mode
	push rax
	mov rax, qword ptr SVM_TO_VMCB_PA[rax]
	vmload rax
	vmrun rax
	vmsave rax
	pop rax
	;Save guest registers, load host registers
	mov qword ptr SVM_TO_RBX[rax], rbx
	mov qword ptr SVM_TO_RCX[rax], rcx
	mov qword ptr SVM_TO_RDX[rax], rdx
	mov qword ptr SVM_TO_RSI[rax], rsi
	mov qword ptr SVM_TO_RDI[rax], rdi
	mov qword ptr SVM_TO_RBP[rax], rbp
	mov qword ptr SVM_TO_R8[rax], r8
	mov qword ptr SVM_TO_R9[rax], r9
	mov qword ptr SVM_TO_R10[rax], r10
	mov qword ptr SVM_TO_R11[rax], r11
	mov qword ptr SVM_TO_R12[rax], r12
	mov qword ptr SVM_TO_R13[rax], r13
	mov qword ptr SVM_TO_R14[rax], r14
	mov qword ptr SVM_TO_R15[rax], r15
	pop rbp

	;restore abi non-volatile registers
	pop rbx
	pop rsi
	pop rdi
	pop r15
	pop r14
	pop r13
	pop r12
	ret
__asm_svm_vcpu_run endp

	end
