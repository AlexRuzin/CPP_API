#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "crypt library: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "crypt library: Compiling 32-bit.")
#endif

#include "inline.h"

#include "api.h"
#include "common/mem.h"
#include "debug/debug.h"

#include "external/asmlen.h"

inline_asm::ASM_ERROR inline_asm::hook_intro(__inout inline_asm::PHOOK_INFO hook_info)
{
	// Test all pointers
	if (cIsBadWritePtr(hook_info->function_address, hook_info->patch_inst_len)) return inline_asm::ER_ASM_PATCH;

	// Create patch buffer
	hook_info->patch_buffer = (LPVOID)cVirtualAlloc(NULL, types::PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (hook_info->patch_buffer == NULL) return inline_asm::ER_ASM_PATCH;
	mem::zeromem(hook_info->patch_buffer, types::PAGE_SIZE);
	mem::copy(hook_info->patch_buffer, hook_info->function_address, hook_info->patch_inst_len);
	*(inline_asm::POPCODE_BYTE)((DWORD_PTR)hook_info->patch_buffer + hook_info->patch_inst_len) = 
		*inline_asm::opcode_list[inline_asm::OPCODE_MOV_EAX].buffer;
	*(inline_asm::POPERAND_DWORD)((DWORD_PTR)hook_info->patch_buffer + hook_info->patch_inst_len + inline_asm::opcode_list[inline_asm::OPCODE_MOV_EAX].size) =
		(OPERAND_DWORD)hook_info->return_address;
	*(inline_asm::POPCODE_WORD)((DWORD_PTR)hook_info->patch_buffer + hook_info->patch_inst_len + inline_asm::opcode_list[inline_asm::OPCODE_MOV_EAX].size +
		sizeof(inline_asm::OPERAND_DWORD)) = *(inline_asm::POPCODE_WORD)inline_asm::opcode_list[inline_asm::OPCODE_JMP_EAX].buffer;

	mem::set(hook_info->function_address, *(PBYTE)inline_asm::opcode_list[OPCODE_NOP].buffer, 
		hook_info->patch_inst_len);

#ifdef DEBUG_OUT
	DBGOUT("Patching %d bytes.", hook_info->patch_inst_len);
#endif

	inline_asm::OPERAND_DWORD relative_offset;
	if ((DWORD_PTR)hook_info->function_address > (DWORD_PTR)hook_info->handler_address) {
		relative_offset = ~((DWORD_PTR)hook_info->function_address - (DWORD_PTR)hook_info->handler_address) - 5;
	} else {
		relative_offset = (DWORD_PTR)hook_info->handler_address - (DWORD_PTR)hook_info->function_address - 6;
	}
	switch (inline_asm::use_interrupt) 
	{
	case true:
		// 0xcc
		*(inline_asm::POPCODE_BYTE)hook_info->function_address = *inline_asm::opcode_list[inline_asm::OPCODE_INT3].buffer;

		// Jmp rel32 opcode
		*(inline_asm::POPCODE_BYTE)((DWORD_PTR)hook_info->function_address  + inline_asm::opcode_list[inline_asm::OPCODE_INT3].size) =
			*inline_asm::opcode_list[inline_asm::OPCODE_JMP_REL32].buffer;

		// Stamp in operand32
		*(inline_asm::POPERAND_DWORD)((DWORD_PTR)hook_info->function_address + inline_asm::opcode_list[inline_asm::OPCODE_INT3].size +
			inline_asm::opcode_list[inline_asm::OPCODE_JMP_REL32].size) = relative_offset;
		break;
	case false:
		// 0xcc
		*(inline_asm::POPCODE_BYTE)hook_info->function_address = *inline_asm::opcode_list[inline_asm::OPCODE_NOP].buffer;

		// Jmp rel32 opcode
		*(inline_asm::POPCODE_BYTE)((DWORD_PTR)hook_info->function_address  + inline_asm::opcode_list[inline_asm::OPCODE_NOP].size) =
			*inline_asm::opcode_list[inline_asm::OPCODE_JMP_REL32].buffer;

		// Stamp in operand32
		*(inline_asm::POPERAND_DWORD)((DWORD_PTR)hook_info->function_address + inline_asm::opcode_list[inline_asm::OPCODE_NOP].size +
			inline_asm::opcode_list[inline_asm::OPCODE_JMP_REL32].size) = relative_offset;
		break;
	}

	return ER_ASM_OK;
}

inline_asm::DISASM_ERROR inline_asm::disasm_get_amount_to_patch(__in LPVOID address, 
	__in UINT min_bytes_to_patch, 
	__out PUINT amount_to_patch)
{

	// Call into asmlen.cpp (recursive)
	*amount_to_patch = 0;
	DWORD instruction_length;
	while (*amount_to_patch < min_bytes_to_patch) {
		get_asm_len((PDWORD)((DWORD_PTR)address + *amount_to_patch), &instruction_length);
		if (instruction_length == 0) {
			*amount_to_patch = 0;
			return inline_asm::DISASM_ER_FAIL;
		}
		*amount_to_patch += (UINT)instruction_length;
	}

	return inline_asm::DISASM_ER_OK;
}

#ifdef __cplusplus
extern "C" {
#endif
HMODULE		get_kernel32_base32(VOID)
{
	HMODULE			base_address;

	/*
	 xor ebx, ebx               // clear ebx
	 mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
	 mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
	 mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	 mov ebx, [ ebx ]           // get the next entry (2nd entry)
	 mov ebx, [ ebx ]           // get the next entry (3rd entry)
	 mov ebx, [ ebx + 0x10 ]    // get the 3rd entries base address (kernel32.dll)
	*/
#ifndef WIN64
	__asm {
		xor		ebx, ebx
		mov		ebx, fs:[0x30]
		mov		ebx, [ebx + 0x0c]
		mov		ebx, [ebx + 0x14]
		mov		ebx, [ebx]
		mov		ebx, [ebx]
		mov		ebx, [ebx + 0x10]
		mov		base_address, ebx
	}
#else
	return GetModuleHandleA("kernel32.dll");
#endif

	return base_address;
}

HMODULE		get_local_dll_base(VOID)
{
	void		*base;

#ifndef WIN64
	__asm {
		nop
		call	delta
delta:
		pop		ebx
		and		ebx, 0ffff0000h
		xor		eax, eax

main_loop:
		mov		ax, [ebx]
		cmp		ax, 'ZM'
		je		exit_loop

		sub		ebx, 1000h
		jmp		main_loop

exit_loop:
		mov		base, ebx
	}
#else
	return (HMODULE)GetModuleHandleA(NULL);
#endif

	return (HMODULE)base;
}

#ifdef __cplusplus
}
#endif

