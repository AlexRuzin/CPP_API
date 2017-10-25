#include <Windows.h>

#include "loader.h"
#include "../api.h"
#include "../common/mem.h"

using namespace loader;

bool loader::check_pe_headers(LPVOID raw_pe, UINT raw_pe_size)
{
	if (raw_pe == NULL || raw_pe_size == 0) return false;

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)raw_pe;
	if (dos_header->e_magic != 'ZM') return false;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)raw_pe + dos_header->e_lfanew);
	if (cIsBadReadPtr((const void *)nt_headers, sizeof(IMAGE_NT_HEADERS)) != false || nt_headers->Signature != 'EP') return false;

	return true;
}

LPTHREAD_START_ROUTINE loader::load_raw_into_virtual(LPVOID raw, UINT raw_size)
{
	if (raw == NULL || check_pe_headers(raw, raw_size) == false) return NULL;

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)raw;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)raw + dos_header->e_lfanew);

	cVirtualFree((LPVOID)nt_headers->OptionalHeader.ImageBase, nt_headers->OptionalHeader.SizeOfImage, MEM_RELEASE);
	LPVOID virtual_base = (LPVOID)cVirtualAlloc((LPVOID)nt_headers->OptionalHeader.ImageBase, 
		nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if ((DWORD_PTR)virtual_base != nt_headers->OptionalHeader.ImageBase) {
		cVirtualFree(virtual_base, nt_headers->OptionalHeader.SizeOfImage, MEM_RELEASE);
		return NULL;
	}

	// Copy 
	mem::copy(virtual_base, raw, nt_headers->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER current_section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);
	for (UINT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		if (current_section->SizeOfRawData == 0 || current_section->PointerToRawData == 0) {
			continue;
		}

		mem::copy((LPVOID)((DWORD_PTR)virtual_base + current_section->VirtualAddress),
			(LPCVOID)((DWORD_PTR)raw + current_section->PointerToRawData),
			current_section->SizeOfRawData);
	}

	resolve_iat(virtual_base);
	LPTHREAD_START_ROUTINE oep = (LPTHREAD_START_ROUTINE)((DWORD_PTR)virtual_base + (DWORD_PTR)nt_headers->OptionalHeader.AddressOfEntryPoint);
	return oep;
}

VOID loader::resolve_iat(LPVOID virtual_base)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)virtual_base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)virtual_base + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);

	DWORD file_offset = (DWORD)((nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
		- section->VirtualAddress) + section->Misc.PhysicalAddress);
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)virtual_base + 
		(DWORD_PTR)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (TRUE) {
		LPSTR module_name = (LPSTR)((DWORD_PTR)import_descriptor->Name + (DWORD_PTR)virtual_base);
		HMODULE module = cLoadLibraryA(module_name);
		if (module == NULL) {
			import_descriptor++;
			if (import_descriptor->OriginalFirstThunk == 0) break;

			continue;
		}

		PIMAGE_THUNK_DATA32 thunk_data = (PIMAGE_THUNK_DATA32)((DWORD_PTR)virtual_base + (DWORD_PTR)import_descriptor->FirstThunk);

		// Ordinal
		if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
			__asm {nop};
		} else {
			//RVA (name)
			while (TRUE) {
				if (thunk_data->u1.AddressOfData == 0) break;

				PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)thunk_data->u1.AddressOfData +
					(DWORD_PTR)virtual_base);

				DWORD function = (DWORD)cGetProcAddress(module, (LPCSTR)import_by_name->Name);
				if (function == 0 || function == thunk_data->u1.Function) {
					thunk_data++;
					continue;
				}

				thunk_data->u1.Function = function;
				thunk_data++;
			}
		}
		import_descriptor++;
		if (import_descriptor->OriginalFirstThunk == 0) break;
	}
}