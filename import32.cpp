#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "J:/_api/config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "import32: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "import32: Compiling 32-bit.")
#endif

//#define __cplusplus
#ifdef __cplusplus
extern "C"
#endif

#include "common\inline.h"
#include "common\str.h"
#include "debug\error.h"

#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))

HMODULE	(__stdcall *f_LoadLibraryA_I32)(LPCSTR file_name)				= NULL;
INT		(__stdcall *f_GetProcAddress_I32)(HANDLE module, LPCSTR name)	= NULL;
BOOL	(__stdcall *f_IsBadReadPtr_I32)(const VOID *ptr, UINT_PTR size) = NULL;
typedef struct {
	HMODULE kernel32;
	LPVOID *loadlibrary;
	LPVOID *getprocaddress;
	LPVOID *isbadreadptr;
} LOADING_FUNCTIONS, *PLOADING_FUNCTIONS;
LOADING_FUNCTIONS functions = {NULL, (LPVOID *)&f_LoadLibraryA_I32, (LPVOID *)&f_GetProcAddress_I32, (LPVOID *)&f_IsBadReadPtr_I32};

LPVOID	resolve_export(HMODULE module, LPCSTR function);
bool	resolve_loading_functions(PLOADING_FUNCTIONS functions);

static const PCHAR getprocaddress_string	= "GetProcAddress";
static const PCHAR loadlibrary_string		= "LoadLibraryA";
static const PCHAR isbadreadptr_string		= "IsBadReadPtr";

VOID resolve_local_api32(VOID)
{
	functions.kernel32 = get_kernel32_base32();
	if (functions.kernel32 == NULL) error::halt_dll(error::ER_GET_KERNEL32, error::default_halt_code);

	bool resolve_status = resolve_loading_functions(&functions);
	if (resolve_status == false) error::halt_dll(error::ER_GET_KERNEL32, error::default_halt_code);
	
	LPVOID image_base = get_local_dll_base();
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_base + dos_header->e_lfanew);

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
	types::OFFSET32 file_offset = (types::OFFSET32)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		- section_header->VirtualAddress + section_header->Misc.PhysicalAddress;
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)image_base
		+ (DWORD_PTR)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (TRUE) {
		LPSTR module_name = (LPSTR)((DWORD_PTR)image_base + import_descriptor->Name);
		HMODULE module = f_LoadLibraryA_I32(module_name);
		if (module == NULL) {
			import_descriptor++;
			if (import_descriptor->FirstThunk == 0) break;
			continue;
		}

		PIMAGE_THUNK_DATA32 thunk_data = (PIMAGE_THUNK_DATA32)((DWORD_PTR)image_base + import_descriptor->FirstThunk);
		if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
			// Ordinal
			while (TRUE) {
				if (thunk_data->u1.AddressOfData == 0) break;
				types::ORDINAL32 import_by_ordinal = (types::ORDINAL32)(((DWORD_PTR)image_base + thunk_data->u1.AddressOfData) & 0x0000ffff);
				DWORD function_address = (DWORD)f_GetProcAddress_I32(module, (LPCSTR)import_by_ordinal);
				if (function_address == 0 || function_address == thunk_data->u1.Function) {
					thunk_data++;
					continue;
				}

				thunk_data->u1.Function = function_address;
				thunk_data++;
			}
		} else {
			// Name (RVA)
			while (TRUE) {
				if (thunk_data->u1.AddressOfData == 0) break;

				PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image_base + thunk_data->u1.AddressOfData);
				if (f_IsBadReadPtr_I32(import_by_name->Name, str::ASCII_CHAR)) {
					thunk_data++;
					continue;
				}

				DWORD function_address = (DWORD)f_GetProcAddress_I32(module, (LPCSTR)import_by_name->Name);
				if (function_address == 0 || function_address == thunk_data->u1.Function) {
					thunk_data++;
					continue;
				}

				thunk_data->u1.Function = function_address;
				thunk_data++;
			}
		}
		import_descriptor++;
		if (import_descriptor->OriginalFirstThunk == 0) break;
	}

	return;
}

static bool resolve_loading_functions(const PLOADING_FUNCTIONS functions)
{
	if (functions == false || functions->kernel32 == NULL) return false;

	*functions->getprocaddress = (INT (__stdcall *)(HANDLE, LPCSTR))resolve_export(functions->kernel32, getprocaddress_string);
	*functions->loadlibrary = (HMODULE (__stdcall *)(LPCSTR))resolve_export(functions->kernel32, loadlibrary_string);
	*functions->isbadreadptr = (BOOL (__stdcall *)(const VOID *, UINT_PTR))resolve_export(functions->kernel32, isbadreadptr_string);

	return true;
}

static LPVOID resolve_export(HMODULE module, LPCSTR function)
{
	PIMAGE_DOS_HEADER dos_header	= (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY eat		= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dos_header + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD name_ptr		= (PDWORD)	((DWORD_PTR)dos_header + eat->AddressOfNames);
	PWORD ordinal_ptr	= (PWORD)	((DWORD_PTR)dos_header + eat->AddressOfNameOrdinals);

	INT ordinal = -1;
	for (UINT i = 0; i < eat->NumberOfNames; i++) {

		PCHAR name_string = (PCHAR)((DWORD_PTR)dos_header + name_ptr[i]);

		if (str::compareA(name_string, function, str::lenA(function)) == 0) {
			ordinal = (UINT)ordinal_ptr[i];
			break;
		}
	}

	LPVOID return_function = 0;
	if (ordinal != -1) {
		PDWORD addr_ptr		= (PDWORD)((DWORD_PTR)dos_header + eat->AddressOfFunctions);
		return_function	= (LPVOID)((DWORD_PTR)dos_header + addr_ptr[ordinal]);
	}

	return return_function;
}
