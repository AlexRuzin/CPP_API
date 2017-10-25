#include <Windows.h>

#pragma once

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef __cplusplus
#define __cplusplus
#endif

#ifdef CONFIG_COMPILE64
#pragma message ("WIN64_OVERRIDE defined in inline.h. Testing only.")
#else
#ifndef BREAK
#define BREAK __asm{ int 3 }
#else
#pragma message ("WIN64_OVERRIDE not defined (inline)")
#endif

#ifndef NOP
#define NOP __asm{nop}
#endif
#endif


// For patching: use interrupt instead of nop
#define NSPR_USE_PATCH_INTERRUPT false;


namespace inline_asm {
	typedef DWORD ASM_ERROR;
	enum {
		ER_ASM_OK,
		ER_ASM_GENERAL_FAILURE,
		ER_ASM_PATCH
	};

	typedef BYTE	OPCODE,			*POPCODE;
	typedef BYTE	OPCODE_BYTE,	*POPCODE_BYTE;
	typedef WORD	OPCODE_WORD,	*POPCODE_WORD;
	typedef WORD	OPCODE_MODRM,	*POPCODE_MODRM;
	typedef DWORD	OPCODE_DWORD,	*POPCODE_DWORD;
	typedef DWORD	OPERAND_DWORD,	*POPERAND_DWORD;

	// Opcodes
	static const OPCODE_BYTE	nspr_mov_eax_opcode		=		0xb8;
	static const OPCODE_MODRM	nspr_jmp_eax_opcode		=		0xe0ff;
	static const OPCODE_BYTE	nspr_jmp_rel32_opcode	=		0xe9;
	static const OPCODE_BYTE	nspr_nop_opcode			=		0x90;
	static const OPCODE_BYTE	nspr_int3_opcode		=		0xcc;

	typedef struct opcode_data {
		UINT		size;
		PBYTE		buffer;
	} OPCODE_DATA, *POPCODE_DATA;

	enum opcode_index {
		OPCODE_MOV_EAX,
		OPCODE_JMP_EAX,
		OPCODE_JMP_REL32,
		OPCODE_NOP,
		OPCODE_INT3
	};

	// Installs an interrupt on the patched code, instead of nop
	const bool use_interrupt = NSPR_USE_PATCH_INTERRUPT;

	// Size of operand32
	const UINT operand32_size = sizeof(DWORD);

	const OPCODE_DATA opcode_list[sizeof(opcode_index) + 1] = {
		{1,		(PBYTE)&nspr_mov_eax_opcode},
		{2,		(PBYTE)&nspr_jmp_eax_opcode},
		{1,		(PBYTE)&nspr_jmp_rel32_opcode},
		{1,		(PBYTE)&nspr_nop_opcode},
		{1,		(PBYTE)&nspr_int3_opcode}
	};

	typedef struct hook_info {
		LPVOID			function_address;
		LPVOID			handler_address;
		LPVOID			patch_buffer;
		LPVOID			return_address;
		UINT			patch_inst_len;
	} HOOK_INFO, *PHOOK_INFO;

	ASM_ERROR hook_intro(__inout PHOOK_INFO hook_info);

	// Disassembler
	typedef DWORD DISASM_ERROR;
	enum {
		DISASM_ER_OK,
		DISASM_ER_FAIL
	};

	DISASM_ERROR disasm_get_amount_to_patch(__in LPVOID address, __in UINT min_bytes_to_patch, 	__out PUINT amount_to_patch);
};

#ifdef __cplusplus
extern "C" {
#endif

// Returns kernel32
HMODULE	get_kernel32_base32(VOID);

// Returns local base
HMODULE	get_local_dll_base(VOID);
}