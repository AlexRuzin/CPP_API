// When using this file, do not call LoadLibraryA/GetProcAddress, etc, the loader will handle everything.
#include <Windows.h>

#pragma once

#include "api.h"
//#include "config.h"
#include "common/str.h"
#include "crypt/crypt.h"

#define API_HASHING_SEED		0x8f31accd		//Hashing seed used by murmur hash in api.c

// Config & api
#define HASHING_SEED			API_HASHING_SEED
#define API_STRLEN				str::lenA
#define API_STRCMP				str::compareA
#define MURMUR_HASH				crypt::murmur_hash

#define			__inopt			__in
#define			__outopt		__out
#define			__inoutopt		__inout
#define			CHECK_VALID(x)	check_function_validity(x)

// Libraries
#define API_KERNEL32			"kernel32.dll"
#define API_SHELL32				"shell32.dll"
#define API_SHLWAPI				"Shlwapi.dll"
#define API_NTDLL				"ntdll.dll"
#define API_ADVAPI32			"Advapi32.lib"
#define API_USER32				"user32.dll"
#define API_WININET				"wininet.dll"
#define API_MSVCRT				"msvcrt.dll"

/*
#ifndef PROCESSINFOCLASS
#undef PROCESSINFOCLASS
typedef INT PROCESSINFOCLASS;
#endif
*/



//Local prototypes
LPVOID	resolve_function(DWORD hash, LPCSTR module);
HMODULE	get_kernel32_base32(VOID);
LPVOID	resolve_export(HMODULE module, DWORD function_hash);
VOID	check_function_validity(LPVOID address);
VOID uninitialize_api(VOID);

static DWORD function_hash_chain[] = {
	0xe956c60d,								// GetModuleFileNameA
	0xa183e1d4,								// ExitProcess
	0x1170140d,								// SHGetFolderPathA
	0x65527fa5,								// PathCombineA
	0xd52c08ed,								// CreateFileA
	0x22e02b3e,								// GetFileSize
	0x10e1aa49,								// HeapAlloc
	0xd0355dd3,								// GetProcessHeap
	0x81d71534,								// ReadFile
	0xc3c02c6f,								// CloseHandle
	0x18bf6c3a,								// GetModuleHandleA
	0x0b405b9d,								// CreateProcessA
	0x0dbdf0a6,								// HeapFree
	0xab849384,								// HeapReAlloc
	0xe34d464b,								// VirtualAlloc
	0xa1ecf70b,								// VirtualAllocEx
	0xb16fceb1,								// WriteProcessMemory
	0xb4becdac,								// ReadProcessMemory
	0xe39e1af0,								// GetThreadContext
	0xa37e1c4c,								// SetThreadContext
	0x36998b62,								// ResumeThread
	0xd236a42d,								// ExpandEnvironmentStringsA
	0xefc194e2,								// GetCurrentProcess
	0xe73ca65c,								// PathGetFileNameA
	0xbcdbe222,								// CreateRemoteThread
	0x9bfaa46a,								// OutputDebugStringA
	0x2d4f6fbc,								// ZwQueryInformationProcess
	0xabde30f6,								// Sleep
	0x650cc772,								// CreateEventA
	0x8db83eb5,								// GetLastError
	0x51e159a1,								// OpenEventA
	0x35b4e7ac,								// CreateToolhelp32Snapshot
	0x1a6a18f0,								// Process32First
	0x4ac087a5,								// Process32Next
	0xeae5a3ff,								// OpenProcessToken
	0x918ae104,								// AdjustTokenPrivileges
	0xffb550f9,								// OpenProcess
	0x86b036be,								// VirtualProtect
	0x55fbbf1d,								// GetCurrentProcessId
	0xbbdb757f,								// GetCurrentThreadId
	0xa33fb389,								// Thread32First
	0x4de81b73,								// OpenThread
	0x1b394954,								// SuspendThread
	0x90f9b158,								// Thread32Next
	0x9a5815b2,								// RtlInitializeCriticalSection (using kernel32 prototypes)
	0xdb577f5e,								// RtlEnterCriticalSection (same story here)
	0x9d6f5edb,								// RtlLeaveCriticalSection (same here)
	0xec2fc599,								// VirtualQuery
	0x4442dde2,								// WriteFile
	0x3d5102c1,								// wvsprintfA
	0x65e98e7a,								// wvsprintfW
	0x021064af,								// OutputDebugStringW
	0x00000000,								// CharLowerA
	0x00000000,								// InternetCrackUrlA
	0x685ad700,								// GetSystemTime
	0x00000000,								// CryptAcquireContextW
	0x00000000,								// CryptCreateHash
	0x00000000,								// CryptHashData
	0x00000000,								// CryptGetHashParam
	0x00000000,								// CryptDestroyHash
	0x00000000,								// CryptReleaseContext
	0x00000000,								// GetLocalTime
	0x00000000,								// MultiByteToWideCHar
	0x00000000,								// StrCmpNICA
	0x021064af,								// HeapCreate
	0x99fed221,								// vsnprintf
	0x443d04fd,								// CreateThread
	0xf866fb74,								// VirtualFree
	0x8bc559cd,								// InternetQueryOptionA
	0x529a5ea7,								// HttpQueryInfoA
	0x8376b2fe,								// FindResourceA
	0x883d5006,								// LoadResource
	0x0fc99434,								// LockResource
	0x44680349,								// SizeofResource
	0x01302832,								// IsBadReadPtr
	0xac248778,								// CreateDirectoryA
	0x9c3a0845,								// IsBadWritePtr
	0xc76fa148,								// CreateMutexA
	0x9c488ecc,								// ReleaseMutex
	0x42078b9d,								// OpenMutexA
	0xd8ba821f,								// WaitForSingleObject
	0xdd700fbe,								// SetEvent
	0xbb4968aa,								// DeleteFileA
	0x342a6233,								// GetCommandLineA
	0x18509741,								// HeapSize
	0x188b80b9,								// TerminateThread
	0xe9cd8201,								// DeleteCriticalSection
	0xdbb02786,								// InternetOpenA
	0xa9290b3c,								// InternetCloseHandle
	0xbcdae6d0,								// InternetOpenUrlA
	0x8fac2920,								// InternetReadFile
	0xecd029e7,								// SetFilePointer
	0x55086987								// GetCurrentDirectoryA
};

/*
DWORD WINAPI GetModuleFileName(
  _In_opt_  HMODULE hModule,
  _Out_     LPTSTR lpFilename,
  _In_      DWORD nSize
);*/
DWORD (WINAPI *f_GetModuleFileNameA)(__inopt HMODULE module, __out LPSTR file_name, __in UINT size_of_buffer) = NULL;
DWORD cGetModuleFileNameA(	__inopt		HMODULE		module,
							__out		LPSTR		file_name,
							__in		UINT		size_of_buffer)
{
	if (f_GetModuleFileNameA == NULL) {
		f_GetModuleFileNameA = (DWORD (WINAPI *)(HMODULE, LPSTR, UINT))resolve_function(function_hash_chain[0], API_KERNEL32);
		CHECK_VALID(f_GetModuleFileNameA);
	}

	return f_GetModuleFileNameA(module, file_name, size_of_buffer);
}

/*
VOID WINAPI ExitProcess(
  _In_  UINT uExitCode
);*/
VOID (WINAPI *f_ExitProcess)(__in UINT exit_code) = NULL;
VOID cExitProcess(__in UINT exit_code)
{
	if (f_ExitProcess == NULL) {
		f_ExitProcess = (VOID (WINAPI *)(UINT))resolve_function(function_hash_chain[1], API_KERNEL32);
		//CHECK_VALID(f_ExitProcess); <- To prevent infinite recursion FIXME
	}

	f_ExitProcess(exit_code);
}

/*
HRESULT SHGetFolderPath(
  _In_   HWND hwndOwner,
  _In_   int nFolder,
  _In_   HANDLE hToken,
  _In_   DWORD dwFlags,
  _Out_  LPTSTR pszPath
);*/
HRESULT (WINAPI *f_SHGetFolderPathA)(__in HWND owner, __in INT folder_type, __in HANDLE token, __in DWORD flags, __out LPSTR path) = NULL;
HRESULT cSHGetFolderPathA(	__in	HWND		owner,
							__in    INT			folder_type,
							__in	HANDLE		token,
							__in	DWORD		flags,
							__out	LPSTR		path)
{
	if (f_SHGetFolderPathA == NULL) {
		f_SHGetFolderPathA = (HRESULT (WINAPI *)(HWND, INT, HANDLE, DWORD, LPSTR))resolve_function(function_hash_chain[2], API_SHELL32);
		CHECK_VALID(f_SHGetFolderPathA);
	}

	return f_SHGetFolderPathA(owner, folder_type, token, flags, path);
}

/*
LPTSTR PathCombine(
  _Out_     LPTSTR pszPathOut,
  _In_opt_  LPCTSTR pszPathIn,
  _In_      LPCTSTR pszMore
);*/
LPTSTR (WINAPI *f_PathCombineA)(__out LPSTR path_out, __inopt LPCSTR path_in, __in LPCSTR more) = NULL;
LPTSTR cPathCombineA(	__out		LPSTR		path_out,
						__inopt		LPCSTR		path_in,
						__in		LPCSTR		more)
{
	if (f_PathCombineA == NULL) {
		f_PathCombineA = (LPTSTR (WINAPI *)(LPSTR, LPCSTR, LPCSTR))resolve_function(function_hash_chain[3], API_SHLWAPI);
		CHECK_VALID(f_PathCombineA);
	}

	return f_PathCombineA(path_out, path_in, more);
}

/*
HANDLE WINAPI CreateFile(
  _In_      LPCTSTR lpFileName,
  _In_      DWORD dwDesiredAccess,
  _In_      DWORD dwShareMode,
  _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_      DWORD dwCreationDisposition,
  _In_      DWORD dwFlagsAndAttributes,
  _In_opt_  HANDLE hTemplateFile
);*/
HANDLE (WINAPI *f_CreateFileA)(__in LPCSTR file_name, __in DWORD access, __in DWORD share, __inopt LPSECURITY_ATTRIBUTES security,
								__in DWORD creation_disposition, __in DWORD flags, __inopt HANDLE template_file) = NULL;
HANDLE cCreateFileA(	__in		LPCSTR					file_name,
						__in		DWORD					access,
						__in		DWORD					share_mode,
						__inopt		LPSECURITY_ATTRIBUTES	security,
						__in		DWORD					creation_disposition,
						__in		DWORD					flags,
						__inopt		HANDLE					template_file)
{
	if (f_CreateFileA == NULL) {
		f_CreateFileA = (HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
			DWORD, DWORD, HANDLE))resolve_function(function_hash_chain[4], API_KERNEL32);
		CHECK_VALID(f_CreateFileA);
	}

	return f_CreateFileA(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}

/*
DWORD WINAPI GetFileSize(
  _In_       HANDLE hFile,
  _Out_opt_  LPDWORD lpFileSizeHigh
);*/
DWORD (WINAPI *f_GetFileSize)(__in HANDLE file, __outopt LPDWORD file_size_high) = NULL;
DWORD cGetFileSize(	__in		HANDLE		file,
					__outopt	LPDWORD		file_size_high)
{
	if (f_GetFileSize == NULL) {
		f_GetFileSize = (DWORD (WINAPI *)(HANDLE, LPDWORD))resolve_function(function_hash_chain[5], API_KERNEL32);
		CHECK_VALID(f_GetFileSize);
	}

	return f_GetFileSize(file, file_size_high);
}

/*
LPVOID WINAPI HeapAlloc(
  _In_  HANDLE hHeap,
  _In_  DWORD dwFlags,
  _In_  SIZE_T dwBytes
);*/
LPVOID (WINAPI *f_HeapAlloc)(__in HANDLE heap, __in DWORD flags, UINT size) = NULL;
LPVOID cHeapAlloc(	__in		HANDLE		heap,
					__in		DWORD		flags,
					__in		UINT		size)
{
	if (f_HeapAlloc == NULL) {
		f_HeapAlloc = (LPVOID (WINAPI *)(HANDLE, DWORD, UINT))resolve_function(function_hash_chain[6], API_KERNEL32);
		CHECK_VALID(f_HeapAlloc);
	}

	return f_HeapAlloc(heap, flags, size);
}

//HANDLE WINAPI GetProcessHeap(void);
HANDLE (WINAPI *f_GetProcessHeap)(VOID) = NULL;
HANDLE cGetProcessHeap(VOID)
{
	if (f_GetProcessHeap == NULL) {
		f_GetProcessHeap = (LPVOID (WINAPI *)(VOID))resolve_function(function_hash_chain[7], API_KERNEL32);
		CHECK_VALID(f_GetProcessHeap);
	}

	return f_GetProcessHeap();
}

/*
BOOL WINAPI ReadFile(
  _In_         HANDLE hFile,
  _Out_        LPVOID lpBuffer,
  _In_         DWORD nNumberOfBytesToRead,
  _Out_opt_    LPDWORD lpNumberOfBytesRead,
  _Inout_opt_  LPOVERLAPPED lpOverlapped
);*/
BOOL (WINAPI *f_ReadFile)(__in HANDLE file, __out LPVOID buffer, __in UINT bytes_to_read, __outopt LPUINT bytes_read,
	__inoutopt LPOVERLAPPED overlapped) = NULL;
BOOL cReadFile(	__in		HANDLE		file,
				__out		LPVOID		buffer,
				__in		UINT		bytes_to_read,
				__outopt	LPUINT		bytes_read,
				__inoutopt  LPOVERLAPPED overlapped)
{
	if (f_ReadFile == NULL) {
		f_ReadFile = (BOOL (WINAPI *)(HANDLE, LPVOID, UINT, LPUINT, LPOVERLAPPED))resolve_function(function_hash_chain[8], API_KERNEL32);
		CHECK_VALID(f_ReadFile);
	}

	return f_ReadFile(file, buffer, bytes_to_read, bytes_read, overlapped);
}

/*BOOL WINAPI CloseHandle(
  _In_  HANDLE hObject
);*/

BOOL (WINAPI *f_CloseHandle)(__in HANDLE object);
BOOL cCloseHandle(	__in		HANDLE		object)
{
	if (f_CloseHandle == NULL) {
		f_CloseHandle = (BOOL (WINAPI *)(HANDLE))resolve_function(function_hash_chain[9], API_KERNEL32);
		CHECK_VALID(f_CloseHandle);
	}

	return f_CloseHandle(object);
}

/*
HMODULE WINAPI GetModuleHandle(
  _In_opt_  LPCTSTR lpModuleName
);*/
HMODULE (WINAPI *f_GetModuleHandleA)(__in LPCTSTR module_name) = NULL;
HMODULE cGetModuleHandleA(__in LPCTSTR module_name)
{
	if (f_GetModuleHandleA == NULL) {
		f_GetModuleHandleA = (HMODULE (WINAPI *)(LPCTSTR))resolve_function(function_hash_chain[10], API_KERNEL32);
		CHECK_VALID(f_GetModuleHandleA);
	}

	return f_GetModuleHandleA(module_name);
}

/*
BOOL WINAPI CreateProcess(
  _In_opt_     LPCTSTR lpApplicationName,
  _Inout_opt_  LPTSTR lpCommandLine,
  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_         BOOL bInheritHandles,
  _In_         DWORD dwCreationFlags,
  _In_opt_     LPVOID lpEnvironment,
  _In_opt_     LPCTSTR lpCurrentDirectory,
  _In_         LPSTARTUPINFO lpStartupInfo,
  _Out_        LPPROCESS_INFORMATION lpProcessInformation
);*/
BOOL (WINAPI *f_CreateProcessA)(__inopt			LPCSTR					application_name,
								__inoutopt		LPSTR					command_line,
								__inopt			LPSECURITY_ATTRIBUTES	process_attributes,
								__inopt			LPSECURITY_ATTRIBUTES	thread_attributes,
								__in			BOOL					inherit_handle,
								__in			DWORD					creation_flags,
								__inopt			LPVOID					environment,
								__inopt			LPCSTR					current_directory,
								__in			LPSTARTUPINFOA			startup_info,
								__out			LPPROCESS_INFORMATION	process_info) = NULL;
BOOL cCreateProcessA(	__inopt			LPCSTR					application_name,
						__inoutopt		LPSTR					command_line,
						__inopt			LPSECURITY_ATTRIBUTES	process_attributes,
						__inopt			LPSECURITY_ATTRIBUTES	thread_attributes,
						__in			BOOL					inherit_handle,
						__in			DWORD					creation_flags,
						__inopt			LPVOID					environment,
						__inopt			LPCSTR					current_directory,
						__in			LPSTARTUPINFOA			startup_info,
						__out			LPPROCESS_INFORMATION	process_info)
{
	if (f_CreateProcessA == NULL) {
		f_CreateProcessA = (BOOL (WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
			BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))resolve_function(function_hash_chain[11], API_KERNEL32);
		CHECK_VALID(f_CreateProcessA);
	}

	return f_CreateProcessA(application_name, command_line, process_attributes, thread_attributes,
		inherit_handle, creation_flags, environment, current_directory, startup_info, process_info);
}

/*
BOOL WINAPI HeapFree(
  _In_  HANDLE hHeap,
  _In_  DWORD dwFlags,
  _In_  LPVOID lpMem
);*/
BOOL (WINAPI *f_HeapFree)(__in HANDLE heap, __in DWORD flags, __in LPVOID memory) = NULL;
BOOL cHeapFree(	__in		HANDLE		heap,
				__in		DWORD		flags,
				__in		LPVOID		memory)
{
	if (f_HeapFree == NULL) {
		f_HeapFree = (BOOL (WINAPI *)(HANDLE, DWORD, LPVOID))resolve_function(function_hash_chain[12], API_KERNEL32);
		CHECK_VALID(f_HeapFree);
	}

	return f_HeapFree(heap, flags, memory);
}

/*
LPVOID WINAPI HeapReAlloc(
  _In_  HANDLE hHeap,
  _In_  DWORD dwFlags,
  _In_  LPVOID lpMem,
  _In_  SIZE_T dwBytes
);*/
LPVOID (WINAPI *f_HeapReAlloc)(__in HANDLE heap, __in DWORD flags, __in LPVOID memory, __in UINT bytes) = NULL;
LPVOID cHeapReAlloc(	__in		HANDLE		heap,
						__in		DWORD		flags,
						__in		LPVOID		memory,
						__in		UINT		bytes)
{
	if (f_HeapReAlloc == NULL) {
		f_HeapReAlloc = (LPVOID (WINAPI *)(HANDLE, DWORD, LPVOID, UINT))resolve_function(function_hash_chain[13], API_KERNEL32);
		CHECK_VALID(f_HeapReAlloc);
	}

	return f_HeapReAlloc(heap, flags, memory, bytes);
}

/*
LPVOID WINAPI VirtualAlloc(
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
);*/
LPVOID (WINAPI *f_VirtualAlloc)(__inopt LPVOID address, __in UINT size, __in DWORD alloc_type, __in DWORD page_security) = NULL;
LPVOID cVirtualAlloc(	__inopt		LPVOID		address,
						__in		UINT		size,
						__in		DWORD		alloc_type,
						__in		DWORD		page_security)
{
	if (f_VirtualAlloc == NULL) {
		f_VirtualAlloc = (LPVOID (WINAPI *)(LPVOID, UINT, DWORD, DWORD))resolve_function(function_hash_chain[14], API_KERNEL32);
		CHECK_VALID(f_VirtualAlloc);
	}

	return f_VirtualAlloc(address, size, alloc_type, page_security);
}

/*
LPVOID WINAPI VirtualAllocEx(
  _In_      HANDLE hProcess,
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
);*/
LPVOID (WINAPI *f_VirtualAllocEx)(	__in		HANDLE		process,
									__inopt		LPVOID		address,
									__in		UINT		size,
									__in		DWORD		alloc_type,
									__in		DWORD		page_security) = NULL;
LPVOID cVirtualAllocEx(	__in		HANDLE		process,
						__inopt		LPVOID		address,
						__in		UINT		size,
						__in		DWORD		alloc_type,
						__in		DWORD		page_security)
{
	if (f_VirtualAllocEx == NULL) {
		f_VirtualAllocEx = (LPVOID (WINAPI *)(HANDLE, LPVOID, UINT, DWORD, DWORD))resolve_function(function_hash_chain[15], API_KERNEL32);
		CHECK_VALID(f_VirtualAllocEx);
	}

	return f_VirtualAllocEx(process, address, size, alloc_type, page_security);
}

/*
BOOL WINAPI WriteProcessMemory(
  _In_   HANDLE hProcess,
  _In_   LPVOID lpBaseAddress,
  _In_   LPCVOID lpBuffer,
  _In_   SIZE_T nSize,
  _Out_  SIZE_T *lpNumberOfBytesWritten
);*/
BOOL (WINAPI *f_WriteProcessMemory)(__in		HANDLE		process,
									__in		LPVOID		base,
									__in		LPCVOID		buffer,
									__in		UINT		size,
									__out		PUINT		written) = NULL;
BOOL cWriteProcessMemory(	__in		HANDLE		process,
							__in		LPVOID		base,
							__in		LPCVOID		buffer,
							__in		UINT		size,
							__out		PUINT		written)
{
	if (f_WriteProcessMemory == NULL) {
		f_WriteProcessMemory = (BOOL (WINAPI *)(HANDLE, LPVOID, LPCVOID, UINT, PUINT))resolve_function(function_hash_chain[16], API_KERNEL32);
		CHECK_VALID(f_WriteProcessMemory);
	}

	return f_WriteProcessMemory(process, base, buffer, size, written);
}

/*
BOOL WINAPI ReadProcessMemory(
  _In_   HANDLE hProcess,
  _In_   LPCVOID lpBaseAddress,
  _Out_  LPVOID lpBuffer,
  _In_   SIZE_T nSize,
  _Out_  SIZE_T *lpNumberOfBytesRead
);*/
BOOL (WINAPI *f_ReadProcessMemory)(	__in		HANDLE		process,
									__in		LPCVOID		base,
									__out		LPVOID		buffer,
									__in		UINT		size,
									__out		PUINT		read) = NULL;
BOOL cReadProcessMemory(	__in		HANDLE		process,
							__in		LPCVOID		base,
							__out		LPVOID		buffer,
							__in		UINT		size,
							__out		PUINT		read)
{
	if (f_ReadProcessMemory == NULL) {
		f_ReadProcessMemory = (BOOL (WINAPI *)(HANDLE, LPCVOID, LPVOID, UINT, PUINT))resolve_function(function_hash_chain[17], API_KERNEL32);
		CHECK_VALID(f_ReadProcessMemory);
	}
	
	return f_ReadProcessMemory(process, base, buffer, size, read);
}

/*
BOOL WINAPI GetThreadContext(
  _In_     HANDLE hThread,
  _Inout_  LPCONTEXT lpContext
);
*/
BOOL (WINAPI *f_GetThreadContext)(	__in		HANDLE		thread,
									__inout		LPCONTEXT	context) = NULL;
BOOL cGetThreadContext(	__in		HANDLE		thread,
						__inout		LPCONTEXT	context)
{
	if (f_GetThreadContext == NULL) {
		f_GetThreadContext = (BOOL (WINAPI *)(HANDLE, LPCONTEXT))resolve_function(function_hash_chain[18], API_KERNEL32);
		CHECK_VALID(f_GetThreadContext);
	}

	return f_GetThreadContext(thread, context);
}

/*
BOOL WINAPI SetThreadContext(
  _In_  HANDLE hThread,
  _In_  const CONTEXT *lpContext
);*/
BOOL (WINAPI *f_SetThreadContext)(__in HANDLE thread, __in const PCONTEXT context) = NULL;
BOOL cSetThreadContext(	__in		HANDLE			thread,
						__in		const PCONTEXT	context)
{
	if (f_SetThreadContext == NULL) {
		f_SetThreadContext = (BOOL (WINAPI *)(HANDLE, const PCONTEXT))resolve_function(function_hash_chain[19], API_KERNEL32);
		CHECK_VALID(f_SetThreadContext);
	}

	return f_SetThreadContext(thread, context);
}

/*
DWORD WINAPI ResumeThread(
  _In_  HANDLE hThread
);*/
DWORD (WINAPI *f_ResumeThread)(__in HANDLE thread) = NULL;
DWORD cResumeThread(	__in		HANDLE		thread)
{
	if (f_ResumeThread == NULL) {
		f_ResumeThread = (DWORD (WINAPI *)(HANDLE))resolve_function(function_hash_chain[20], API_KERNEL32);
		CHECK_VALID(f_ResumeThread);
	}

	return f_ResumeThread(thread);
}

/*
DWORD WINAPI ExpandEnvironmentStrings(
  _In_       LPCTSTR lpSrc,
  _Out_opt_  LPTSTR lpDst,
  _In_       DWORD nSize
);
*/
DWORD (WINAPI *f_ExpandEnvironmentStringsA)(__in LPCTSTR source, __outopt LPTSTR destination, __in UINT size) = NULL;
DWORD cExpandEnvironmentStringsA(	__in		LPCTSTR		source,
									__outopt	LPTSTR		destination,
									__in		UINT		size)
{
	if (f_ExpandEnvironmentStringsA == NULL) {
		f_ExpandEnvironmentStringsA = (DWORD (WINAPI *)(LPCTSTR, LPTSTR, UINT))resolve_function(function_hash_chain[21], API_KERNEL32);
		CHECK_VALID(f_ExpandEnvironmentStringsA);
	}

	return f_ExpandEnvironmentStringsA(source, destination, size);
}

//HANDLE WINAPI GetCurrentProcess(void);
HANDLE (WINAPI *f_GetCurrentProcess)(VOID) = NULL;
HANDLE cGetCurrentProcess(VOID)
{
	if (f_GetCurrentProcess == NULL) {
		f_GetCurrentProcess = (HANDLE (WINAPI *)(VOID))resolve_function(function_hash_chain[22], API_KERNEL32);
		CHECK_VALID(f_GetCurrentProcess);
	}

	return f_GetCurrentProcess();
}

/*
PTSTR PathFindFileName(
  _In_  PTSTR pPath
);*/
LPSTR (WINAPI *f_PathFindFileNameA)(__in LPSTR path);
LPSTR cPathFindFileNameA(	__in	LPSTR		path)
{
	if (f_PathFindFileNameA == NULL) {
		f_PathFindFileNameA = (LPSTR (WINAPI *)(LPSTR))resolve_function(function_hash_chain[23], API_SHLWAPI);
		CHECK_VALID(f_PathFindFileNameA);
	}

	return f_PathFindFileNameA(path);
}

/*
HANDLE WINAPI CreateRemoteThread(
  _In_   HANDLE hProcess,
  _In_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_   SIZE_T dwStackSize,
  _In_   LPTHREAD_START_ROUTINE lpStartAddress,
  _In_   LPVOID lpParameter,
  _In_   DWORD dwCreationFlags,
  _Out_  LPDWORD lpThreadId
);
*/
HANDLE (WINAPI *f_CreateRemoteThread)(	__in		HANDLE						process,
										__in		LPSECURITY_ATTRIBUTES		attributes,
										__in		SIZE_T						stack_size,
										__in		LPTHREAD_START_ROUTINE		oep,
										__in		LPVOID						parameters,
										__in		DWORD						flags,
										__in		LPDWORD						thread_id) = NULL;
HANDLE cCreateRemoteThread(		HANDLE						process,
								LPSECURITY_ATTRIBUTES		attributes,
								SIZE_T						stack_size,
								LPTHREAD_START_ROUTINE		oep,
								LPVOID						parameters,
								DWORD						flags,
								LPDWORD						thread_id)
{
	if (f_CreateRemoteThread == NULL) {
		f_CreateRemoteThread = (HANDLE (WINAPI *)(	HANDLE,
													LPSECURITY_ATTRIBUTES,
													SIZE_T,
													LPTHREAD_START_ROUTINE,
													LPVOID,
													DWORD,
													LPDWORD))resolve_function(function_hash_chain[24], API_KERNEL32);
		CHECK_VALID(f_CreateRemoteThread);
	}

	return f_CreateRemoteThread(process, attributes, stack_size, oep, parameters, flags, thread_id);
}

/*
void WINAPI OutputDebugString(
  _In_opt_  LPCTSTR lpOutputString
);
*/
VOID (WINAPI *f_OutputDebugStringA)( __inopt LPCSTR string) = NULL;
VOID cOutputDebugStringA(LPCSTR string)
{
	if (f_OutputDebugStringA == NULL) {
		f_OutputDebugStringA = (VOID (WINAPI *)(LPCSTR))resolve_function(function_hash_chain[25], API_KERNEL32);
		CHECK_VALID(f_OutputDebugStringA);
	}

	f_OutputDebugStringA(string);

	return;
}

/*
NTSTATUS WINAPI ZwQueryInformationProcess(
  _In_       HANDLE ProcessHandle,
  _In_       PROCESSINFOCLASS ProcessInformationClass,
  _Out_      PVOID ProcessInformation,
  _In_       ULONG ProcessInformationLength,
  _Out_opt_  PULONG ReturnLength
);
*/
NTSTATUS (WINAPI *f_ZwQueryInformationProcess)(		HANDLE				handle,
													PROCESSINFOCLASS	info_class,
													PVOID				process_info,
													ULONG				process_info_length,
													PULONG				return_length) = NULL;
NTSTATUS cZwQueryInformationProcess(	__in		HANDLE				handle,
										__in		PROCESSINFOCLASS	info_class,
										__out		PVOID				process_info,
										__in		ULONG				process_info_length,
										__out_opt	PULONG				return_length)
{
	if (f_ZwQueryInformationProcess == NULL) {
		f_ZwQueryInformationProcess = (NTSTATUS (WINAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
			resolve_function(function_hash_chain[26], API_NTDLL);
		CHECK_VALID(f_ZwQueryInformationProcess);
	}

	return f_ZwQueryInformationProcess(handle, info_class, process_info, process_info_length, return_length);
}

/*
VOID WINAPI Sleep(
  _In_  DWORD dwMilliseconds
);
*/
VOID (WINAPI *f_Sleep)(DWORD time) = NULL;
VOID cSleep(__in DWORD time)
{

	if (f_Sleep == NULL) {
		f_Sleep = (VOID (WINAPI *)(DWORD))resolve_function(function_hash_chain[27], API_KERNEL32);
		CHECK_VALID(f_Sleep);
	}

	return f_Sleep(time);
}

/*
HANDLE WINAPI CreateEvent(
  _In_opt_  LPSECURITY_ATTRIBUTES lpEventAttributes,
  _In_      BOOL bManualReset,
  _In_      BOOL bInitialState,
  _In_opt_  LPCTSTR lpName
);
*/
HANDLE (WINAPI *f_CreateEventA)(LPSECURITY_ATTRIBUTES attributes, BOOL reset, BOOL init_state, LPCSTR name) = NULL;
HANDLE cCreateEventA(	__in_opt	LPSECURITY_ATTRIBUTES	attributes,
						__in		BOOL					reset,
						__in		BOOL					init_state,
						__in_opt	LPCSTR					name)
{
	if (f_CreateEventA == NULL) {
		f_CreateEventA = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR))
			resolve_function(function_hash_chain[28], API_KERNEL32);
		CHECK_VALID(f_CreateEventA);
	}

	return f_CreateEventA(attributes, reset, init_state, name);
}

//DWORD WINAPI GetLastError(void);
DWORD (WINAPI *f_GetLastError)(VOID) = NULL;
DWORD cGetLastError(VOID)
{
	if (f_GetLastError == FALSE) {
		f_GetLastError = (DWORD (WINAPI *)(VOID))resolve_function(function_hash_chain[29], API_KERNEL32);
		CHECK_VALID(f_GetLastError);
	}
	
	return f_GetLastError();
}

/*
HANDLE WINAPI OpenEvent(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  LPCTSTR lpName
);
*/
HANDLE (WINAPI *f_OpenEventA)(DWORD access_level, BOOL inherit_handle, LPCSTR name) = NULL;
HANDLE cOpenEventA(	__in	DWORD		access_level,
					__in	BOOL		inherit_handle,
					__in	LPCSTR		name)
{
	if (f_OpenEventA == NULL) {
		f_OpenEventA = (HANDLE (WINAPI *)(DWORD, BOOL, LPCSTR))
			resolve_function(function_hash_chain[30], API_KERNEL32);
		CHECK_VALID(f_OpenEventA);
	}

	return f_OpenEventA(access_level, inherit_handle, name);
}

/*
HANDLE WINAPI CreateToolhelp32Snapshot(
  _In_  DWORD dwFlags,
  _In_  DWORD th32ProcessID
);
*/
HANDLE (WINAPI *f_CreateToolhelp32Snapshot)(DWORD flags, DWORD pid) = NULL;
HANDLE cCreateToolhelp32Snapshot(	__in	DWORD	flags,
									__in	DWORD	pid)
{
	if (f_CreateToolhelp32Snapshot == NULL) {
		f_CreateToolhelp32Snapshot = (HANDLE (WINAPI *)(DWORD, DWORD))resolve_function(function_hash_chain[31], API_KERNEL32);
		CHECK_VALID(f_CreateToolhelp32Snapshot);
	}

	return f_CreateToolhelp32Snapshot(flags, pid);
}

/*
BOOL WINAPI Process32First(
  _In_     HANDLE hSnapshot,
  _Inout_  LPPROCESSENTRY32 lppe
);
*/
BOOL (WINAPI *f_Process32First)(HANDLE snapshot, LPPROCESSENTRY32 lppe) = NULL;
BOOL cProcess32First(	__in		HANDLE				snapshot,
						__inout		LPPROCESSENTRY32	lppe)
{
	if (f_Process32First == NULL) {
		f_Process32First = (BOOL (WINAPI *)(HANDLE, LPPROCESSENTRY32))resolve_function(function_hash_chain[32], API_KERNEL32);
		CHECK_VALID(f_Process32First);
	}

	return f_Process32First(snapshot, lppe);
}

/*
BOOL WINAPI Process32Next(
  _In_   HANDLE hSnapshot,
  _Out_  LPPROCESSENTRY32 lppe
);
*/
BOOL (WINAPI *f_Process32Next)(HANDLE snapshot, LPPROCESSENTRY32 lppe) = NULL;
BOOL cProcess32Next(	__in	HANDLE				snapshot,
						__out	LPPROCESSENTRY32	lppe)
{
	if (f_Process32Next == NULL) {
		f_Process32Next = (BOOL (WINAPI *)(HANDLE, LPPROCESSENTRY32))resolve_function(function_hash_chain[33], API_KERNEL32);
		CHECK_VALID(f_Process32Next);
	}

	return f_Process32Next(snapshot, lppe);
}

/*
BOOL WINAPI OpenProcessToken(
  _In_   HANDLE ProcessHandle,
  _In_   DWORD DesiredAccess,
  _Out_  PHANDLE TokenHandle
);
*/
BOOL (WINAPI *f_OpenProcessToken)(HANDLE handle, DWORD access, PHANDLE token_handle) = NULL;
BOOL cOpenProcessToken(	__in	HANDLE	handle,
						__in	DWORD	access,
						__out	PHANDLE	token_handle)
{
	if (f_OpenProcessToken == NULL) {
		f_OpenProcessToken = (BOOL (WINAPI *)(HANDLE, DWORD, PHANDLE))resolve_function(function_hash_chain[34], API_ADVAPI32);
		CHECK_VALID(f_OpenProcessToken);
	}

	return f_OpenProcessToken(handle, access, token_handle);
}

/*
BOOL WINAPI LookupPrivilegeValue(
  _In_opt_  LPCTSTR lpSystemName,
  _In_      LPCTSTR lpName,
  _Out_     PLUID lpLuid
);
*/
BOOL (WINAPI *f_LookupPrivilegeValueA)(LPCSTR system_name, LPCSTR name, PLUID uid) = NULL;
BOOL cLookupPrivilegeValueA(	__in_opt	LPCSTR	system_name,
								__in		LPCSTR	name,
								__out		PLUID	uid)
{
	if (f_LookupPrivilegeValueA == NULL) {
		f_LookupPrivilegeValueA = (BOOL (WINAPI *)(LPCSTR, LPCSTR, PLUID))resolve_function(function_hash_chain[35], API_ADVAPI32);
		CHECK_VALID(f_LookupPrivilegeValueA);
	}

	return f_LookupPrivilegeValueA(system_name, name, uid);
}

/*
BOOL WINAPI AdjustTokenPrivileges(
  _In_       HANDLE TokenHandle,
  _In_       BOOL DisableAllPrivileges,
  _In_opt_   PTOKEN_PRIVILEGES NewState,
  _In_       DWORD BufferLength,
  _Out_opt_  PTOKEN_PRIVILEGES PreviousState,
  _Out_opt_  PDWORD ReturnLength
);
*/
BOOL (WINAPI *f_AdjustTokenPrivileges)(HANDLE token_handle, BOOL disable_all_privileges,
										PTOKEN_PRIVILEGES new_state, DWORD buffer_length, PTOKEN_PRIVILEGES old_state,
										PDWORD return_length) = NULL;
BOOL cAdjustTokenPrivileges(	__in		HANDLE				token_handle,
								__in		BOOL				disable_all_privileges,
								__in_opt	PTOKEN_PRIVILEGES	new_state,
								__in		DWORD				buffer_length,
								__out_opt	PTOKEN_PRIVILEGES	previous_state,
								__out_opt	PDWORD				return_length)
{
	if (f_AdjustTokenPrivileges == NULL) {
		f_AdjustTokenPrivileges = (BOOL (WINAPI *)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD))
			resolve_function(function_hash_chain[36], API_ADVAPI32);
		CHECK_VALID(f_AdjustTokenPrivileges);
	}

	return f_AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, buffer_length, previous_state, return_length);
}

/*
HANDLE WINAPI OpenProcess(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  DWORD dwProcessId
);
*/
HANDLE (WINAPI *f_OpenProcess)(DWORD access, BOOL inherit_handle, DWORD pid) = NULL;
HANDLE cOpenProcess(	__in	DWORD	access,
						__in	BOOL	inherit_handle,
						__in	DWORD	pid)
{
	if (f_OpenProcess == NULL) {
		f_OpenProcess = (HANDLE (WINAPI *)(DWORD, BOOL, DWORD))resolve_function(function_hash_chain[36], API_KERNEL32);
		CHECK_VALID(f_OpenProcess);
	}

	return f_OpenProcess(access, inherit_handle, pid);
}

/*
BOOL WINAPI VirtualProtect(
  _In_   LPVOID lpAddress,
  _In_   SIZE_T dwSize,
  _In_   DWORD flNewProtect,
  _Out_  PDWORD lpflOldProtect
);
*/
BOOL (WINAPI *f_VirtualProtect)(LPVOID address, SIZE_T size, DWORD new_protect, PDWORD old_protect) = NULL;
BOOL cVirtualProtect(	__in	LPVOID		address,
						__in	SIZE_T		size,
						__in	DWORD		new_protect,
						__out	PDWORD		old_protect)
{
	if (f_VirtualProtect == NULL) {
		f_VirtualProtect = (BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD))resolve_function
			(function_hash_chain[37], API_KERNEL32);
		CHECK_VALID(f_VirtualProtect);
	}

	return f_VirtualProtect(address, size, new_protect, old_protect);
}

// DWORD WINAPI GetCurrentProcessId(void);
DWORD (WINAPI *f_GetCurrentProcessId)(VOID) = NULL;
DWORD cGetCurrentProcessId(VOID)
{
	if (f_GetCurrentProcessId == NULL) {
		f_GetCurrentProcessId = (DWORD (WINAPI *)(VOID))resolve_function(function_hash_chain[38], API_KERNEL32);
		CHECK_VALID(f_GetCurrentProcessId);
	}

	return f_GetCurrentProcessId();
}

// DWORD WINAPI GetCurrentThreadId(void);
DWORD (WINAPI *f_GetCurrentThreadId)(VOID) = NULL;
DWORD cGetCurrentThreadId(VOID)
{
	if (f_GetCurrentThreadId == NULL) {
		f_GetCurrentThreadId = (DWORD (WINAPI *)(VOID))resolve_function(function_hash_chain[39], API_KERNEL32);
		CHECK_VALID(f_GetCurrentThreadId);
	}

	return f_GetCurrentThreadId();
}

/*
BOOL WINAPI Thread32First(
  _In_     HANDLE hSnapshot,
  _Inout_  LPTHREADENTRY32 lpte
);
*/
BOOL (WINAPI *f_Thread32First)(HANDLE snapshot, LPTHREADENTRY32 thread_entry) = NULL;
BOOL cThread32First(	__in		HANDLE			snapshot,
						__inout		LPTHREADENTRY32	thread_entry)
{
	if (f_Thread32First == NULL) {
		f_Thread32First = (BOOL (WINAPI *)(HANDLE, LPTHREADENTRY32))resolve_function(
			function_hash_chain[40], API_KERNEL32);
		CHECK_VALID(f_Thread32First);
	}

	return f_Thread32First(snapshot, thread_entry);
}

/*
HANDLE OpenThread(
  DWORD dwDesiredAccess,
  BOOL bInheritHandle,
  DWORD dwThreadId
);
*/
HANDLE (WINAPI *f_OpenThread)(DWORD access, BOOL inherit_handle, DWORD tid) = NULL;
HANDLE cOpenThread(	__in	DWORD	access,
					__in	BOOL	inherit_handle,
					__in	DWORD	tid)
{
	if (f_OpenThread == NULL) {
		f_OpenThread = (HANDLE (WINAPI *)(DWORD, BOOL, DWORD))resolve_function(function_hash_chain[41], API_KERNEL32);
		CHECK_VALID(f_OpenThread);
	}

	return f_OpenThread(access, inherit_handle, tid);
}

/*
DWORD WINAPI SuspendThread(
  _In_  HANDLE hThread
);
*/
DWORD (WINAPI *f_SuspendThread)(HANDLE thread) = NULL;
DWORD cSuspendThread(__in		HANDLE	thread)
{
	if (f_SuspendThread == NULL) {
		f_SuspendThread = (DWORD (WINAPI *)(HANDLE))resolve_function(function_hash_chain[42], API_KERNEL32);
		CHECK_VALID(f_SuspendThread);
	}

	return f_SuspendThread(thread);
}


/*
BOOL WINAPI Thread32Next(
  _In_   HANDLE hSnapshot,
  _Out_  LPTHREADENTRY32 lpte
);
*/
BOOL (WINAPI *f_Thread32Next)(HANDLE snapshot, LPTHREADENTRY32 thread_entry) = NULL;
BOOL cThread32Next(	__in	HANDLE				snapshot,
					__out	LPTHREADENTRY32		thread_entry)
{
	if (f_Thread32Next == NULL) {
		f_Thread32Next = (BOOL (WINAPI *)(HANDLE, LPTHREADENTRY32))resolve_function(function_hash_chain[43], API_KERNEL32);
		CHECK_VALID(f_Thread32Next);
	}

	return f_Thread32Next(snapshot, thread_entry);
}


// NOTE: Although InitializeCriticalSection (and others) are exported in kernel32, we will resolve 
// RtlInitializeCriticalSection in ntdll and use the kernel32 prototypes instead. This is due to a 
// negligable limitation of our resolver (it is unable to perform far API resolutions aka kernel32 ->
// ntdll export)

/*
void WINAPI InitializeCriticalSection(
  _Out_  LPCRITICAL_SECTION lpCriticalSection
);
*/
VOID (WINAPI *f_InitializeCriticalSection)(LPCRITICAL_SECTION critical_section) = NULL;
VOID cInitializeCriticalSection(__out LPCRITICAL_SECTION critical_section)
{
	
	if (f_InitializeCriticalSection == NULL) {
		f_InitializeCriticalSection = (VOID (WINAPI *)(LPCRITICAL_SECTION))
			resolve_function(function_hash_chain[44], API_NTDLL);
		CHECK_VALID(f_InitializeCriticalSection);
	}
	//f_InitializeCriticalSection = (VOID (WINAPI *)(LPCRITICAL_SECTION))
	//	cGetProcAddress(cLoadLibraryA("kernel32.dll"), "InitializeCriticalSection");

	return f_InitializeCriticalSection(critical_section);
}

/*
void WINAPI EnterCriticalSection(
  _Inout_  LPCRITICAL_SECTION lpCriticalSection
);
*/
VOID (WINAPI *f_EnterCriticalSection)(LPCRITICAL_SECTION critical_section) = NULL;
VOID cEnterCriticalSection(__inout LPCRITICAL_SECTION critical_section)
{
	if (f_EnterCriticalSection == NULL) {
		f_EnterCriticalSection = (VOID (WINAPI *)(LPCRITICAL_SECTION))
			resolve_function(function_hash_chain[45], API_NTDLL);
		CHECK_VALID(f_EnterCriticalSection);
	}

	return f_EnterCriticalSection(critical_section);
}

/*
void WINAPI LeaveCriticalSection(
  _Inout_  LPCRITICAL_SECTION lpCriticalSection
);
*/
VOID (WINAPI *f_LeaveCriticalSection)(LPCRITICAL_SECTION critical_section) = NULL;
VOID cLeaveCriticalSection(__inout LPCRITICAL_SECTION critical_section)
{
	if (f_LeaveCriticalSection == NULL) {
		f_LeaveCriticalSection = (VOID (WINAPI *)(LPCRITICAL_SECTION))
			resolve_function(function_hash_chain[46], API_NTDLL);
		CHECK_VALID(f_LeaveCriticalSection);
	}

	return f_LeaveCriticalSection(critical_section);
}

/*
SIZE_T WINAPI VirtualQuery(
  _In_opt_  LPCVOID lpAddress,
  _Out_     PMEMORY_BASIC_INFORMATION lpBuffer,
  _In_      SIZE_T dwLength
);
*/
SIZE_T (WINAPI *f_VirtualQuery)(LPCVOID address, PMEMORY_BASIC_INFORMATION mem_info, SIZE_T len) = NULL;
SIZE_T cVirtualQuery(	__inopt	LPCVOID						address,
						__out	PMEMORY_BASIC_INFORMATION	buffer,
						__in	SIZE_T						len)
{
	if (f_VirtualQuery == NULL) {
		f_VirtualQuery = (SIZE_T (WINAPI *)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))
			resolve_function(function_hash_chain[47], API_KERNEL32);
		CHECK_VALID(f_VirtualQuery);
	}

	return f_VirtualQuery(address, buffer, len);
}

/*
BOOL WINAPI WriteFile(
  _In_         HANDLE hFile,
  _In_         LPCVOID lpBuffer,
  _In_         DWORD nNumberOfBytesToWrite,
  _Out_opt_    LPDWORD lpNumberOfBytesWritten,
  _Inout_opt_  LPOVERLAPPED lpOverlapped
);
*/
BOOL (WINAPI *f_WriteFile)(HANDLE file, LPCVOID buffer, DWORD size, LPDWORD written, LPOVERLAPPED overlapped) = NULL;
BOOL cWriteFile(	__in			HANDLE				file,
					__in			LPCVOID				buffer,
					__in			DWORD				size,
					__outopt		LPDWORD				written,
					__inoutopt		LPOVERLAPPED		overlapped)
{
	if (f_WriteFile == NULL) {
		f_WriteFile = (BOOL (WINAPI *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))
			resolve_function(function_hash_chain[48], API_KERNEL32);
		CHECK_VALID(f_WriteFile);
	}

	return f_WriteFile(file, buffer, size, written, overlapped);
}

/*
int WINAPI wvsprintf(
  _Out_  LPTSTR lpOutput,
  _In_   LPCTSTR lpFmt,
  _In_   va_list arglist
);
*/

INT (WINAPI *f_wvsprintfA)(LPSTR output, LPCSTR format_list, va_list list) = NULL;
INT cwvsprintfA(__out	LPSTR		output,
				__in	LPCSTR		format_list,
				__in	va_list		list)
{
	if (f_wvsprintfA == NULL) {
		f_wvsprintfA = (INT (WINAPI *)(LPSTR, LPCSTR, va_list))resolve_function(function_hash_chain[49], API_USER32);
		CHECK_VALID(f_wvsprintfA);
	}

	return f_wvsprintfA(output, format_list, list);
}

INT (WINAPI *f_wvsprintfW)(LPTSTR output, LPCTSTR format_list, va_list list) = NULL;
INT cwvsprintfW(LPTSTR output, LPCTSTR format_list, va_list list)
{
	if (f_wvsprintfW == NULL) {
		f_wvsprintfW = (INT (WINAPI *)(LPTSTR, LPCTSTR, va_list))resolve_function(function_hash_chain[50], API_USER32);
		CHECK_VALID(f_wvsprintfW);
	}

	return f_wvsprintfW(output, format_list, list);
}

/*
void WINAPI OutputDebugString(
  _In_opt_  LPCTSTR lpOutputString
);
*/
VOID (WINAPI *f_OutputDebugStringW)(LPCTSTR string) = NULL;
VOID cOutputDebugStringW(__inopt LPCTSTR string)
{
	if (f_OutputDebugStringW == NULL) {
		f_OutputDebugStringW = (VOID (WINAPI *)(LPCTSTR))resolve_function(function_hash_chain[51], API_KERNEL32);
		CHECK_VALID(f_OutputDebugStringW);
	}

	return f_OutputDebugStringW(string);
}

/*
LPTSTR WINAPI CharLower(
  _Inout_  LPTSTR lpsz
);*/
LPSTR (WINAPI *f_CharLowerA)(LPSTR string) = NULL;
LPSTR cCharLowerA(LPSTR string)
{
	if (f_CharLowerA == NULL) {
		f_CharLowerA = (LPSTR (WINAPI *)(LPSTR))resolve_function(function_hash_chain[52], API_USER32);
		CHECK_VALID(f_CharLowerA);
	}

	return f_CharLowerA(string);
}

/*
BOOL InternetCrackUrl(
  _In_     LPCTSTR lpszUrl,
  _In_     DWORD dwUrlLength,
  _In_     DWORD dwFlags,
  _Inout_  LPURL_COMPONENTS lpUrlComponents
);
*/
BOOL (WINAPI * f_InternetCrackUrlA)(LPCSTR url, DWORD len, DWORD flags, LPURL_COMPONENTS url_components) = NULL;
BOOL cInternetCrackUrlA(	__in	LPCSTR				url,
							__in	DWORD				len,
							__in	DWORD				flags,
							__inout	LPURL_COMPONENTS	url_components)
{
	if (f_InternetCrackUrlA == NULL) {
		f_InternetCrackUrlA = (BOOL (WINAPI *)(LPCSTR, DWORD, DWORD, LPURL_COMPONENTS))
			resolve_function(function_hash_chain[53], API_WININET);
		CHECK_VALID(f_InternetCrackUrlA);
	}

	return f_InternetCrackUrlA(url, len, flags, url_components);
}

/*
void WINAPI GetSystemTime(
  _Out_  LPSYSTEMTIME lpSystemTime
);
*/
VOID (WINAPI *f_GetSystemTime)(LPSYSTEMTIME system_time) = NULL;
VOID cGetSystemTime(__out LPSYSTEMTIME system_time)
{
	if (f_GetSystemTime == NULL) {
		f_GetSystemTime = (VOID (WINAPI *)(LPSYSTEMTIME))resolve_function(function_hash_chain[54], API_KERNEL32);
		CHECK_VALID(f_GetSystemTime);
	}

	return f_GetSystemTime(system_time);
}

/*
BOOL WINAPI CryptAcquireContext(
  _Out_  HCRYPTPROV *phProv,
  _In_   LPCTSTR pszContainer,
  _In_   LPCTSTR pszProvider,
  _In_   DWORD dwProvType,
  _In_   DWORD dwFlags
);
*/
BOOL (WINAPI *f_CryptAcquireContextW)(HCRYPTPROV *provider, LPCWSTR container, LPCWSTR zProvider, DWORD type, DWORD flags) = NULL;
BOOL cCryptAcquireContextW(	__out	HCRYPTPROV		*provider,
							__in	LPCWSTR			container,
							__in	LPCWSTR			zProvider,
							__in	DWORD			type,
							__in	DWORD			flags)
{
	if (f_CryptAcquireContextW == NULL) {
		f_CryptAcquireContextW = (BOOL (WINAPI *)(HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD))
			resolve_function(function_hash_chain[55], API_ADVAPI32);
		CHECK_VALID(f_CryptAcquireContextW);
	}

	return f_CryptAcquireContextW(provider, container, zProvider, type, flags);
}

/*
BOOL WINAPI CryptCreateHash(
  _In_   HCRYPTPROV hProv,
  _In_   ALG_ID Algid,
  _In_   HCRYPTKEY hKey,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTHASH *phHash
);
*/
BOOL (WINAPI *f_CryptCreateHash)(HCRYPTPROV provider, ALG_ID algo_id, HCRYPTKEY key, DWORD flags, HCRYPTHASH *hash) = NULL;
BOOL cCryptCreateHash(	__in	HCRYPTPROV		provider,
						__in	ALG_ID			algo_id,
						__in	HCRYPTKEY		key,
						__in	DWORD			flags,
						__out	HCRYPTHASH*		hash)
{
	if (f_CryptCreateHash == NULL) {
		f_CryptCreateHash = (BOOL (WINAPI *)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*))
			resolve_function(function_hash_chain[56], API_ADVAPI32);
		CHECK_VALID(f_CryptCreateHash);
	}

	return f_CryptCreateHash(provider, algo_id, key, flags, hash);
}

/*
BOOL WINAPI CryptHashData(
  _In_  HCRYPTHASH hHash,
  _In_  BYTE *pbData,
  _In_  DWORD dwDataLen,
  _In_  DWORD dwFlags
);
*/
BOOL (WINAPI *f_CryptHashData)(HCRYPTHASH hash, PBYTE data, DWORD len, DWORD flags) = NULL;
BOOL cCryptHashData(__in HCRYPTHASH		hash,
					__in PBYTE			data,
					__in DWORD			len,
					__in DWORD			flags)
{
	if (f_CryptHashData == NULL) {
		f_CryptHashData = (BOOL (WINAPI *)(HCRYPTHASH, PBYTE, DWORD, DWORD))
			resolve_function(function_hash_chain[57], API_ADVAPI32);
		CHECK_VALID(f_CryptHashData);
	}

	return f_CryptHashData(hash, data, len, flags);
}

/*
BOOL WINAPI CryptGetHashParam(
  _In_     HCRYPTHASH hHash,
  _In_     DWORD dwParam,
  _Out_    BYTE *pbData,
  _Inout_  DWORD *pdwDataLen,
  _In_     DWORD dwFlags
);
*/
BOOL (WINAPI *f_CryptGetHashParam)(HCRYPTHASH hash, DWORD parm, PBYTE data, PDWORD data_len, DWORD flags) = NULL;
BOOL cCryptGetHashParam(	__in	HCRYPTHASH	hash,
							__in	DWORD		parm,
							__out	PBYTE		data,
							__inout PDWORD		data_len,
							__in	DWORD		flags)
{
	if (f_CryptGetHashParam == NULL) {
		f_CryptGetHashParam = (BOOL (WINAPI *)(HCRYPTHASH, DWORD, PBYTE, PDWORD, DWORD))
			resolve_function(function_hash_chain[58], API_ADVAPI32);
		CHECK_VALID(f_CryptGetHashParam);
	}

	return f_CryptGetHashParam(hash, parm, data, data_len, flags);
}

/*
BOOL WINAPI CryptDestroyHash(
  _In_  HCRYPTHASH hHash
);*/
BOOL (WINAPI *f_CryptDestroyHash)(HCRYPTHASH hash) = NULL;
BOOL cCryptDestroyHash(__in HCRYPTHASH hash)
{
	if (f_CryptDestroyHash == NULL) {
		f_CryptDestroyHash = (BOOL (WINAPI *)(HCRYPTHASH))resolve_function(function_hash_chain[59], API_ADVAPI32);
		CHECK_VALID(f_CryptDestroyHash);
	}

	return f_CryptDestroyHash(hash);

}

/*
BOOL WINAPI CryptReleaseContext(
  _In_  HCRYPTPROV hProv,
  _In_  DWORD dwFlags
);
*/
BOOL (WINAPI *f_CryptReleaseContext)(HCRYPTPROV provider, DWORD flags) = NULL;
BOOL cCryptReleaseContext(__in HCRYPTPROV	provider,
						  __in DWORD		flags)
{
	if (f_CryptReleaseContext == NULL) {
		f_CryptReleaseContext = (BOOL (WINAPI *)(HCRYPTPROV, DWORD))resolve_function(function_hash_chain[60], API_ADVAPI32);
		CHECK_VALID(f_CryptReleaseContext);
	}

	return f_CryptReleaseContext(provider, flags);
}

/*
void WINAPI GetLocalTime(
  _Out_  LPSYSTEMTIME lpSystemTime
);
*/

 VOID (WINAPI *f_GetLocalTime)(LPSYSTEMTIME system_time) = NULL;
 VOID cGetLocalTime(__out LPSYSTEMTIME system_time)
 {
	 if (f_GetLocalTime == NULL) {
		 f_GetLocalTime = (VOID (WINAPI *)(LPSYSTEMTIME))resolve_function(function_hash_chain[61], API_KERNEL32);
		 CHECK_VALID(f_GetLocalTime);
	 }
	 
	 return f_GetLocalTime(system_time);
 }

 /*
 int MultiByteToWideChar(
  _In_       UINT CodePage,
  _In_       DWORD dwFlags,
  _In_       LPCSTR lpMultiByteStr,
  _In_       int cbMultiByte,
  _Out_opt_  LPWSTR lpWideCharStr,
  _In_       int cchWideChar
);*/
 INT (WINAPI *f_MultiByteToWideChar)(UINT code_page, DWORD flags, LPCSTR multibytestr, INT multi_count, LPWSTR widecharstr, INT wide_count) = NULL;
 INT cMultiByteToWideChar(	__in	UINT		code_page,
							__in	DWORD		flags,
							__in	LPCSTR		multibytestr,
							__in	INT			multi_count,
							__outopt LPWSTR		widecharstr,
							__in	INT			wide_count)
 {
	 if (f_MultiByteToWideChar == NULL) {
		 f_MultiByteToWideChar = (INT (WINAPI *)(UINT, DWORD, LPCSTR, INT, LPWSTR, INT))
			 resolve_function(function_hash_chain[62], API_KERNEL32);
		 CHECK_VALID(f_MultiByteToWideChar);
	 }

	 return f_MultiByteToWideChar(code_page, flags, multibytestr, multi_count, widecharstr, wide_count);
 }

 /*
 int StrCmpNIC(
  _In_  LPCTSTR pszStr1,
  _In_  LPCTSTR pszStr2,
  int nChar
);
*/
 INT (WINAPI *fStrCmpNICA)(LPCSTR str1, LPCSTR str2, INT nChar) = NULL;
 INT cStrCmpNICA(LPCSTR str1, LPCSTR str2, INT nChar)
 {
	 if (fStrCmpNICA == NULL) {
		 fStrCmpNICA = (INT (WINAPI *)(LPCSTR, LPCSTR, INT))resolve_function(function_hash_chain[63], API_SHLWAPI);
		 CHECK_VALID(fStrCmpNICA);
	 }

	 return fStrCmpNICA(str1, str2, nChar);
 }

 /*
 HANDLE WINAPI HeapCreate(
  _In_  DWORD flOptions,
  _In_  SIZE_T dwInitialSize,
  _In_  SIZE_T dwMaximumSize
);
*/
 HANDLE (WINAPI *f_HeapCreate)(DWORD options, SIZE_T init_size, SIZE_T max_size) = NULL;
 HANDLE cHeapCreate(DWORD options, SIZE_T init_size, SIZE_T max_size)
 {
	 if (f_HeapCreate == NULL) {
		 f_HeapCreate = (HANDLE (WINAPI *)(DWORD, SIZE_T, SIZE_T))resolve_function(function_hash_chain[64], API_KERNEL32);
		 CHECK_VALID(f_HeapCreate);
	 }

	 return f_HeapCreate(options, init_size, max_size);
 }

 /*
 int vsnprintf(
   char *buffer,
   size_t count,
   const char *format,
   va_list argptr 
);
*/
 INT (_cdecl *f_vsnprintfA)(LPCSTR buffer, SIZE_T count, LPCSTR format, va_list argptr) = NULL;
 INT cvsnprintfA(LPCSTR buffer, SIZE_T count, LPCSTR format, va_list argptr)
 {
	 if (f_vsnprintfA == NULL) {
		 f_vsnprintfA = (INT (_cdecl *)(LPCSTR, SIZE_T, LPCSTR, va_list))resolve_function(function_hash_chain[65], API_MSVCRT);
		 CHECK_VALID(f_vsnprintfA);
	 }

	 return f_vsnprintfA(buffer, count, format, argptr);
 }

 /*
 HANDLE WINAPI CreateThread(
  _In_opt_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_       SIZE_T dwStackSize,
  _In_       LPTHREAD_START_ROUTINE lpStartAddress,
  _In_opt_   LPVOID lpParameter,
  _In_       DWORD dwCreationFlags,
  _Out_opt_  LPDWORD lpThreadId
);
*/
 HANDLE (WINAPI *f_CreateThread)(LPSECURITY_ATTRIBUTES attributes, SIZE_T stack_size, LPTHREAD_START_ROUTINE oep, LPVOID parameter,
	 DWORD flags, LPDWORD tid) = NULL;
 HANDLE cCreateThread(	__inopt		LPSECURITY_ATTRIBUTES		attributes,
						__in		SIZE_T						stack_size,
						__in		LPTHREAD_START_ROUTINE		oep,
						__inopt		LPVOID						parameter,
						__in		DWORD						flags,
						__outopt	LPDWORD						tid)
 {
	 if (f_CreateThread == NULL) {
		 f_CreateThread = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
			 DWORD, LPDWORD))resolve_function(function_hash_chain[66], API_KERNEL32);
		 CHECK_VALID(f_CreateThread);
	 }

	 return f_CreateThread(attributes, stack_size, oep, parameter, flags, tid);
 }

 /*
 BOOL WINAPI VirtualFree(
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD dwFreeType
);
 */
 BOOL (WINAPI *f_VirtualFree)(LPVOID address, SIZE_T size, DWORD type) = NULL;
 BOOL cVirtualFree(	__in LPVOID		address,
					__in SIZE_T		size,
					__in DWORD		type)
 {
	 if (f_VirtualFree == NULL) {
		 f_VirtualFree = (BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD))resolve_function(function_hash_chain[67], API_KERNEL32);
		 CHECK_VALID(f_VirtualFree);
	 }

	 return f_VirtualFree(address, size, type);
 }

 /*
 BOOL InternetQueryOption(
  _In_     HINTERNET hInternet,
  _In_     DWORD dwOption,
  _Out_    LPVOID lpBuffer,
  _Inout_  LPDWORD lpdwBufferLength
);*/
 BOOL (WINAPI *f_InternetQueryOption)(HINTERNET internet, DWORD option, LPVOID buffer, LPDWORD buffer_length) = NULL;
 BOOL cInternetQueryOptionA(	__in	HINTERNET	internet,
								__in	DWORD		option,
								__out	LPVOID		buffer,
								__inout LPDWORD		buffer_length)
 {
	 if (f_InternetQueryOption == NULL) {
		 f_InternetQueryOption = (BOOL (WINAPI *)(HINTERNET, DWORD, LPVOID, LPDWORD))resolve_function(function_hash_chain[68], API_WININET);
		 CHECK_VALID(f_InternetQueryOption);
	 }

	 return f_InternetQueryOption(internet, option, buffer, buffer_length);
 }

 /*
 BOOL HttpQueryInfo(
  _In_     HINTERNET hRequest,
  _In_     DWORD dwInfoLevel,
  _Inout_  LPVOID lpvBuffer,
  _Inout_  LPDWORD lpdwBufferLength,
  _Inout_  LPDWORD lpdwIndex
);
*/
BOOL (WINAPI *f_HttpQueryInfoA)(HINTERNET request, DWORD level, LPVOID buffer, LPDWORD buffer_length, LPDWORD index) = NULL;
BOOL cHttpQueryInfoA(	__in		HINTERNET	request,
					__in		DWORD		level,
					__inout		LPVOID		buffer,
					__inout		LPDWORD		buffer_length,
					__inout		LPDWORD		index)
{
	if (f_HttpQueryInfoA == NULL) {
	f_HttpQueryInfoA = (BOOL (WINAPI *)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD))resolve_function(function_hash_chain[69], API_WININET);
	CHECK_VALID(f_HttpQueryInfoA);
	}

	return f_HttpQueryInfoA(request, level, buffer, buffer_length, index);
}

 /*
 HRSRC WINAPI FindResource(
  _In_opt_  HMODULE hModule,
  _In_      LPCTSTR lpName,
  _In_      LPCTSTR lpType
);
*/
HRSRC (WINAPI *f_FindResourceA)(HMODULE module, LPCSTR name, LPCSTR type) = NULL;
HRSRC cFindResourceA(	__in_opt	HMODULE		module,
					__in		LPCSTR		name,
					__in		LPCSTR		type)
{
	if (f_FindResourceA == NULL) {
		f_FindResourceA = (HRSRC (WINAPI *)(HMODULE, LPCSTR, LPCSTR))resolve_function(function_hash_chain[70], API_KERNEL32);
		CHECK_VALID(f_FindResourceA);
	}

	return f_FindResourceA(module, name, type);
}

 /*
 HGLOBAL WINAPI LoadResource(
  _In_opt_  HMODULE hModule,
  _In_      HRSRC hResInfo
);
*/
HGLOBAL (WINAPI *f_LoadResource)(HMODULE module, HRSRC resource_info) = NULL;
HGLOBAL cLoadResource(	__in_opt	HMODULE		module,
					__in		HRSRC		resource_info)
{
	if (f_LoadResource == NULL) {
		f_LoadResource = (HGLOBAL (WINAPI *)(HMODULE, HRSRC))resolve_function(function_hash_chain[71], API_KERNEL32);
		CHECK_VALID(f_LoadResource);
	}

	return f_LoadResource(module, resource_info);
}

 /*
 LPVOID WINAPI LockResource(
  _In_  HGLOBAL hResData
);
*/
LPVOID (WINAPI *f_LockResource)(HGLOBAL resource_data) = NULL;
LPVOID cLockResource(__in HGLOBAL resource_data)
{
	if (f_LockResource == NULL) {
		f_LockResource = (LPVOID (WINAPI *)(HGLOBAL))resolve_function(function_hash_chain[72], API_KERNEL32);
		CHECK_VALID(f_LockResource);
	}

	return f_LockResource(resource_data);
}

/*
DWORD WINAPI SizeofResource(
  _In_opt_  HMODULE hModule,
  _In_      HRSRC hResInfo
);
*/
DWORD (WINAPI *f_SizeofResource)(HMODULE module, HRSRC resource_info) = NULL;
DWORD cSizeofResource(	__in_opt	HMODULE		module,
						__in		HRSRC		resource_info)
{
	if (f_SizeofResource == NULL) {
		f_SizeofResource = (DWORD (WINAPI *)(HMODULE, HRSRC))resolve_function(function_hash_chain[73], API_KERNEL32);
		CHECK_VALID(f_SizeofResource);
	}

	return f_SizeofResource(module, resource_info);
}

/*
BOOL WINAPI IsBadReadPtr(
  _In_  const VOID *lp,
  _In_  UINT_PTR ucb
);
*/
BOOL (WINAPI *f_IsBadReadPtr)(const VOID *lp, UINT_PTR ucb) = NULL;
BOOL cIsBadReadPtr(	__in	const VOID		*lp,
					__in	UINT_PTR		ucb)
{
	if (f_IsBadReadPtr == NULL) {
		f_IsBadReadPtr = (BOOL (WINAPI *)(const VOID *, UINT_PTR))resolve_function(function_hash_chain[74], API_KERNEL32);
		CHECK_VALID(f_IsBadReadPtr);
	}

	return f_IsBadReadPtr(lp, ucb);
}

/*
BOOL WINAPI CreateDirectory(
  _In_      LPCTSTR lpPathName,
  _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
*/
BOOL (WINAPI *f_CreateDirectoryA)(LPCSTR path_name, LPSECURITY_ATTRIBUTES security_attributes) = NULL;
BOOL cCreateDirectoryA(	__in		LPCSTR					path_name,
						__in_opt	LPSECURITY_ATTRIBUTES	security_attributes)
{
	if (f_CreateDirectoryA == NULL) {
		f_CreateDirectoryA = (BOOL (WINAPI *)(LPCSTR, LPSECURITY_ATTRIBUTES))resolve_function(function_hash_chain[75], API_KERNEL32);
		CHECK_VALID(f_CreateDirectoryA);
	}

	return f_CreateDirectoryA(path_name, security_attributes);
}

/*
BOOL WINAPI IsBadWritePtr(
  _In_  LPVOID lp,
  _In_  UINT_PTR ucb
);
*/
BOOL (WINAPI *f_IsBadWritePtr)(LPVOID lp, UINT_PTR amount) = NULL;
BOOL cIsBadWritePtr(	__in LPVOID		lp,
						__in UINT_PTR	amount)
{
	if (f_IsBadWritePtr == NULL) {
		f_IsBadWritePtr = (BOOL (WINAPI *)(LPVOID, UINT_PTR))resolve_function(function_hash_chain[76], API_KERNEL32);
		CHECK_VALID(f_IsBadWritePtr);
	}

	return f_IsBadWritePtr(lp, amount);
}

/*
HANDLE WINAPI CreateMutex(
  _In_opt_  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  _In_      BOOL bInitialOwner,
  _In_opt_  LPCTSTR lpName
);
*/
HANDLE (WINAPI *f_CreateMutexA)(LPSECURITY_ATTRIBUTES security_attributes, BOOL inital_owner, LPCSTR name) = NULL;
HANDLE cCreateMutexA(	__inopt	LPSECURITY_ATTRIBUTES	security_attributes,
						__in	BOOL					initial_owner,
						__inopt	LPCSTR					name)
{
	if (f_CreateMutexA == NULL) {
		f_CreateMutexA = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR))resolve_function(function_hash_chain[77], API_KERNEL32);
		CHECK_VALID(f_CreateMutexA);
	}

	return f_CreateMutexA(security_attributes, initial_owner, name);
}

/*
BOOL WINAPI ReleaseMutex(
  _In_  HANDLE hMutex
);
*/
BOOL (WINAPI *f_ReleaseMutex)(HANDLE mutex) = NULL;
BOOL cReleaseMutex(__in HANDLE mutex)
{
	if (f_ReleaseMutex == NULL) {
		f_ReleaseMutex = (BOOL (WINAPI *)(HANDLE))resolve_function(function_hash_chain[78], API_KERNEL32);
		CHECK_VALID(f_ReleaseMutex);
	}

	return f_ReleaseMutex(mutex);
}

/*
HANDLE WINAPI OpenMutex(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  LPCTSTR lpName
);
*/
HANDLE (WINAPI *f_OpenMutexA)(DWORD access, BOOL inherit_handle, LPCSTR name) = NULL;
HANDLE cOpenMutexA(	__in DWORD	access,
					__in BOOL	inherit_handle,
					__in LPCSTR name)
{
	if (f_OpenMutexA == NULL) {
		f_OpenMutexA = (HANDLE (WINAPI *)(DWORD, BOOL, LPCSTR))resolve_function(function_hash_chain[79], API_KERNEL32);
		CHECK_VALID(f_OpenMutexA);
	}

	return f_OpenMutexA(access, inherit_handle, name);
}

/*
DWORD WINAPI WaitForSingleObject(
  _In_  HANDLE hHandle,
  _In_  DWORD dwMilliseconds
);
*/
DWORD (WINAPI *f_WaitForSingleObject)(HANDLE handle, DWORD time) = NULL;
DWORD cWaitForSingleObject(	__in	HANDLE	handle,
							__in	DWORD	time)
{
	if (f_WaitForSingleObject == NULL) {
		f_WaitForSingleObject = (DWORD (WINAPI *)(HANDLE, DWORD))resolve_function(function_hash_chain[80], API_KERNEL32);
		CHECK_VALID(f_WaitForSingleObject);
	}

	return f_WaitForSingleObject(handle, time);
}

/*
BOOL WINAPI SetEvent(
  _In_  HANDLE hEvent
);
*/
BOOL (WINAPI *f_SetEvent)(HANDLE event_handle) = NULL;
BOOL cSetEvent(__in HANDLE event_handle)
{
	if (f_SetEvent == NULL) {
		f_SetEvent = (BOOL (WINAPI *)(HANDLE))resolve_function(function_hash_chain[81], API_KERNEL32);
		CHECK_VALID(f_SetEvent);
	}

	return f_SetEvent(event_handle);
}

/*
BOOL WINAPI DeleteFile(
  _In_  LPCTSTR lpFileName
);
*/
BOOL (WINAPI *f_DeleteFileA)(LPCSTR name) = NULL;
BOOL cDeleteFileA(__in LPCSTR name)
{
	if (f_DeleteFileA == NULL) {
		f_DeleteFileA = (BOOL (WINAPI *)(LPCSTR))resolve_function(function_hash_chain[82], API_KERNEL32);
		CHECK_VALID(f_DeleteFileA);
	}

	return f_DeleteFileA(name);
}

//LPTSTR WINAPI GetCommandLine(void);
LPSTR (WINAPI *f_GetCommandLineA)(VOID) = NULL;
LPSTR cGetCommandLineA(VOID)
{
	if (f_GetCommandLineA == NULL) {
		f_GetCommandLineA = (LPSTR (WINAPI *)(VOID))resolve_function(function_hash_chain[83], API_KERNEL32);
		CHECK_VALID(f_GetCommandLineA);
	}

	return f_GetCommandLineA();
}

/*
SIZE_T WINAPI HeapSize(
  _In_  HANDLE hHeap,
  _In_  DWORD dwFlags,
  _In_  LPCVOID lpMem
);
*/
SIZE_T (WINAPI *f_HeapSize)(HANDLE heap, DWORD flags, LPCVOID mem) = NULL;
SIZE_T cHeapSize(	__in HANDLE		heap,
					__in DWORD		flags,
					__in LPCVOID	mem)
{
	if (f_HeapSize == NULL) {
		f_HeapSize = (SIZE_T (WINAPI *)(HANDLE, DWORD, LPCVOID))resolve_function(function_hash_chain[84], API_KERNEL32);
		CHECK_VALID(f_HeapSize);
	}

	return f_HeapSize(heap, flags, mem);
}

/*
BOOL WINAPI TerminateThread(
  _Inout_  HANDLE hThread,
  _In_     DWORD dwExitCode
);
*/
BOOL (WINAPI *f_TerminateThread)(HANDLE thread, DWORD exit_code) = NULL;
BOOL cTerminateThread(	__inout	HANDLE	thread,
						__in	DWORD	exit_code)
{
	if (f_TerminateThread == NULL) {
		f_TerminateThread = (BOOL (WINAPI *)(HANDLE, DWORD))resolve_function(function_hash_chain[85], API_KERNEL32);
		CHECK_VALID(f_TerminateThread);
	}

	return f_TerminateThread(thread, exit_code);
}

/*
void WINAPI DeleteCriticalSection(
  _Inout_  LPCRITICAL_SECTION lpCriticalSection
);
*/
VOID (WINAPI *f_DeleteCriticalSection)(LPCRITICAL_SECTION critical_section) = NULL;
VOID cDeleteCriticalSection(__inout	LPCRITICAL_SECTION critical_section)
{
	if (f_DeleteCriticalSection == NULL) {
		f_DeleteCriticalSection = (VOID (WINAPI *)(LPCRITICAL_SECTION))resolve_function(function_hash_chain[86], API_KERNEL32);
		CHECK_VALID(f_DeleteCriticalSection);
	}

	return f_DeleteCriticalSection(critical_section);
}

/*
HINTERNET InternetOpen(
  _In_  LPCTSTR lpszAgent,
  _In_  DWORD dwAccessType,
  _In_  LPCTSTR lpszProxyName,
  _In_  LPCTSTR lpszProxyBypass,
  _In_  DWORD dwFlags
);
*/
HINTERNET (WINAPI *f_InternetOpenA)(LPCSTR agent, DWORD access_type, LPCSTR proxy_name, LPCSTR proxy_bypass, DWORD flags) 
	= NULL;
HINTERNET cInternetOpenA(	__in	LPCSTR	agent,
							__in	DWORD	access_type,
							__in	LPCSTR	proxy_name,
							__in	LPCSTR	proxy_bypass,
							__in	DWORD	flags)
{
	if (f_InternetOpenA == NULL) {
		f_InternetOpenA = (HINTERNET (WINAPI *)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD))resolve_function(
			function_hash_chain[87], API_WININET);
		CHECK_VALID(f_InternetOpenA);
	}

	return f_InternetOpenA(agent, access_type, proxy_name, proxy_bypass, flags);
}

/*
BOOL InternetCloseHandle(
  _In_  HINTERNET hInternet
);
*/
BOOL (WINAPI *f_InternetCloseHandle)(HINTERNET internet) = NULL;
BOOL cInternetCloseHandle(__in HINTERNET internet)
{
	if (f_InternetCloseHandle == NULL) {
		f_InternetCloseHandle = (BOOL (WINAPI *)(HINTERNET))resolve_function(function_hash_chain[88], API_WININET);
		CHECK_VALID(f_InternetCloseHandle);
	}

	return f_InternetCloseHandle(internet);
}

/*
HINTERNET InternetOpenUrl(
  _In_  HINTERNET hInternet,
  _In_  LPCTSTR lpszUrl,
  _In_  LPCTSTR lpszHeaders,
  _In_  DWORD dwHeadersLength,
  _In_  DWORD dwFlags,
  _In_  DWORD_PTR dwContext
);
*/
HINTERNET (WINAPI *f_InternetOpenUrlA)(HINTERNET internet, LPCSTR url, LPCSTR headers, DWORD headers_len, 
	DWORD flags, DWORD_PTR context) = NULL;
HINTERNET cInternetOpenUrlA(	__in HINTERNET	internet,
								__in LPCSTR		url,
								__in LPCSTR		headers,
								__in DWORD		headers_len,
								__in DWORD		flags,
								__in DWORD_PTR	context)
{
	if (f_InternetOpenUrlA == NULL) {
		f_InternetOpenUrlA = (HINTERNET (WINAPI *)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR))
			resolve_function(function_hash_chain[89], API_WININET);
		CHECK_VALID(f_InternetOpenUrlA);
	}

	return f_InternetOpenUrlA(internet, url, headers, headers_len, flags, context);
}

/*
BOOL InternetReadFile(
  _In_   HINTERNET hFile,
  _Out_  LPVOID lpBuffer,
  _In_   DWORD dwNumberOfBytesToRead,
  _Out_  LPDWORD lpdwNumberOfBytesRead
);
*/
BOOL (WINAPI *f_InternetReadFile)(HINTERNET file, LPVOID buffer, DWORD bytes_to_read, LPDWORD bytes_read) = NULL;
BOOL cInternetReadFile(	__in	HINTERNET	file,
						__out	LPVOID		buffer,
						__in	DWORD		bytes_to_read,
						__out	LPDWORD		bytes_read)
{
	if (f_InternetReadFile == NULL) {
		f_InternetReadFile = (BOOL (WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD))
			resolve_function(function_hash_chain[90], API_WININET);
		CHECK_VALID(f_InternetReadFile);
	}

	return f_InternetReadFile(file, buffer, bytes_to_read, bytes_read);
}

/*
DWORD WINAPI SetFilePointer(
  _In_         HANDLE hFile,
  _In_         LONG lDistanceToMove,
  _Inout_opt_  PLONG lpDistanceToMoveHigh,
  _In_         DWORD dwMoveMethod
);
*/
DWORD (WINAPI *f_SetFilePointer)(HANDLE file, LONG distance_to_move, PLONG distance_to_move_high, 
	DWORD move_method) = NULL;
DWORD cSetFilePointer(	__in		HANDLE	file,
						__in		LONG	distance_to_move,
						__inout_opt	PLONG	distance_to_move_high,
						__in		DWORD	move_method)
{
	if (f_SetFilePointer == NULL) {
		f_SetFilePointer = (DWORD (WINAPI *)(HANDLE, LONG, PLONG, DWORD))
			resolve_function(function_hash_chain[91], API_KERNEL32);
		
		CHECK_VALID(f_SetFilePointer);
	}

	return f_SetFilePointer(file, distance_to_move, distance_to_move_high, move_method);
}

/*
DWORD WINAPI GetCurrentDirectoryA(
  _In_   DWORD nBufferLength,
  _Out_  LPSTR lpBuffer
);
*/
DWORD (WINAPI *f_GetCurrentDirectoryA)(__in DWORD buffer_length, __out LPSTR buffer) = NULL;
DWORD cGetCurrentDirectoryA(	__in	DWORD	buffer_length,
								__out	LPSTR	buffer)
{
	   if (f_GetCurrentDirectoryA == NULL) {
			f_GetCurrentDirectoryA = (DWORD (WINAPI *)(DWORD, LPSTR))
				resolve_function(function_hash_chain[92] , API_KERNEL32);

			CHECK_VALID(f_GetCurrentDirectoryA);
	   }

	   return f_GetCurrentDirectoryA(buffer_length, buffer);
}
/* DO NOT USE
int sprintf_s(
   char *buffer,
   size_t sizeOfBuffer,
   const char *format [,
   argument] ... 
);*/
/*
INT (WINAPI *f_sprintf_s)(PCHAR buffer, SIZE_T size, const PCHAR format, ...) = NULL;
INT csprintf_s(	__inout	PCHAR	buffer,
				__in	SIZE_T	buffer_length,
				__in	PCHAR	format,
				...)
{
	if (f_sprintf_s == NULL) {
		f_sprintf_s = (INT (WINAPI *)(PCHAR, SIZE_T, const PCHAR, ...))resolve_function(function_hash_chain[87], API_MSVCRT);
		CHECK_VALID(f_sprintf_s);
	}

	//return f_sprintf_s(buffer, buffer_length, format, ...);
}*/

///////////////////////////////////////////////////////////////////////////////////////////////

/*
FARPROC WINAPI GetProcAddress(
  _In_  HMODULE hModule,
  _In_  LPCSTR lpProcName
);*/
LPVOID (WINAPI *f_GetProcAddress)(__in HMODULE module, __in LPCSTR procedure_name) = NULL;
LPVOID cGetProcAddress(	__in HMODULE		module,
						__in LPCSTR			procedure_name)
{
	return f_GetProcAddress(module, procedure_name);
}

/*
HMODULE WINAPI LoadLibrary(
  _In_  LPCTSTR lpFileName
);*/
HMODULE (WINAPI *f_LoadLibraryA)(__in LPCSTR file_name) = NULL;
HMODULE cLoadLibraryA(__in LPCSTR file_name)
{
	return f_LoadLibraryA(file_name);
}

static LPVOID resolve_function(DWORD hash, LPCSTR module)
{
	HMODULE			kernel32_base;
	HMODULE			module_base;
	LPVOID			procedure;

	if ((f_GetProcAddress == NULL) && (f_LoadLibraryA == NULL)) {
		// We must first resolve these functions...
		kernel32_base		= get_kernel32_base32();
		f_LoadLibraryA		= (HMODULE (WINAPI *)(LPCSTR))resolve_export(kernel32_base, 0x4dbfb8e4);
		f_GetProcAddress	= (LPVOID (WINAPI *)(HMODULE, LPCSTR))resolve_export(kernel32_base, 0x47d30a54);
	}

	module_base = cLoadLibraryA(module);
	if (module_base == NULL) {
		return NULL;
	}
	procedure   = (LPVOID)resolve_export(module_base, hash);

	return procedure;
}


static HMODULE		get_kernel32_base32(VOID)
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

#ifndef CONFIG_COMPILE64
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
	base_address = LoadLibraryA("kernel32");
#endif


	return base_address;
}

static LPVOID resolve_export(HMODULE module, DWORD function_hash)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_EXPORT_DIRECTORY		eat;

	PDWORD						name_ptr, addr_ptr;
	PWORD						ordinal_ptr;
	LPVOID						return_function = NULL;
	PCHAR						name_string;
	UINT						i, ordinal;

	DWORD						name_hash;

	dos_header	= (PIMAGE_DOS_HEADER)module;
	nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	eat			= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dos_header + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	name_ptr	= (PDWORD)	((DWORD_PTR)dos_header + eat->AddressOfNames);
	ordinal_ptr	= (PWORD)	((DWORD_PTR)dos_header + eat->AddressOfNameOrdinals);

	ordinal = -1;
	for (i = 0; i < eat->NumberOfNames; i++) {

		name_string = (PCHAR)((DWORD_PTR)dos_header + name_ptr[i]);

		name_hash   = MURMUR_HASH(name_string, API_STRLEN(name_string), HASHING_SEED);

		if ((!API_STRCMP(name_string, "HeapAlloc", API_STRLEN("HeapAlloc"))) && (name_hash == function_hash)) {
			// Add in an exception for this one
			if (f_GetProcAddress != NULL) {
				return f_GetProcAddress(module, "HeapAlloc");
			} else {
				return NULL;
			}
		}

		if ((!API_STRCMP(name_string, "HeapReAlloc", API_STRLEN("ReHeapAlloc"))) && (name_hash == function_hash)) {
			// Add in an exception for this one
			if (f_GetProcAddress != NULL) {
				return f_GetProcAddress(module, "HeapReAlloc");
			} else {
				return NULL;
			}
		}

		if (function_hash == name_hash) {
			ordinal = (UINT)ordinal_ptr[i];
			break;
		}

	}

	if (ordinal != -1) {
		addr_ptr		= (PDWORD)((DWORD_PTR)dos_header + eat->AddressOfFunctions);
		return_function	= (LPVOID)((DWORD_PTR)dos_header + addr_ptr[ordinal]);
	}

	return return_function;
}

static VOID check_function_validity(LPVOID address)
{
	if (address != NULL) {
		return;
	} else {
		cExitProcess(0);
	}
}

VOID uninitialize_api(VOID)
{
	f_GetModuleFileNameA						= NULL;
	f_GetProcAddress							= NULL;
	f_LoadLibraryA								= NULL;
	f_GetModuleHandleA							= NULL;
	f_ExitProcess								= NULL;
	f_SHGetFolderPathA							= NULL;
	f_PathCombineA								= NULL;
	f_CreateFileA								= NULL;
	f_GetFileSize								= NULL;
	f_HeapAlloc									= NULL;
	f_GetProcessHeap							= NULL;
	f_ReadFile									= NULL;
	f_CloseHandle								= NULL;
	f_CreateProcessA							= NULL;
	f_HeapFree									= NULL;
	f_HeapReAlloc								= NULL;
	f_VirtualAlloc								= NULL;
	f_VirtualAllocEx							= NULL;
	f_WriteProcessMemory						= NULL;
	f_ReadProcessMemory							= NULL;
	f_GetThreadContext							= NULL;
	f_SetThreadContext							= NULL;
	f_ResumeThread								= NULL;
	f_ExpandEnvironmentStringsA					= NULL;
	f_GetCurrentProcess							= NULL;
	f_PathFindFileNameA							= NULL;
	f_CreateRemoteThread						= NULL;
	f_CreateEventA								= NULL;
	f_OutputDebugStringA						= NULL;
	f_Sleep										= NULL;
	f_GetLastError								= NULL;
	f_OpenEventA								= NULL;
	f_CreateToolhelp32Snapshot					= NULL;
	f_Process32First							= NULL;
	f_Process32Next								= NULL;
	f_OpenProcessToken							= NULL;
	f_LookupPrivilegeValueA						= NULL;
	f_AdjustTokenPrivileges						= NULL;
	f_OpenProcess								= NULL;
	f_VirtualProtect							= NULL;
	f_GetCurrentProcessId						= NULL;
	f_GetCurrentThreadId						= NULL;
	f_Thread32First								= NULL;
	f_OpenThread								= NULL;
	f_SuspendThread								= NULL;
	f_ResumeThread								= NULL;
	f_Thread32Next								= NULL;
	f_InitializeCriticalSection					= NULL;
	f_EnterCriticalSection						= NULL;
	f_LeaveCriticalSection						= NULL;
	f_VirtualQuery								= NULL;
	f_WriteFile									= NULL;
	f_wvsprintfA								= NULL;
	f_wvsprintfW								= NULL;
	f_OutputDebugStringW						= NULL;
	f_CharLowerA								= NULL;
	f_InternetCrackUrlA							= NULL;
	f_GetSystemTime								= NULL;
	f_CryptAcquireContextW						= NULL;
	f_CryptCreateHash							= NULL;
	f_CryptHashData								= NULL;
	f_CryptGetHashParam							= NULL;
	f_CryptDestroyHash							= NULL;
	f_CryptReleaseContext						= NULL;
	f_GetLocalTime								= NULL;
	f_MultiByteToWideChar						= NULL;
	fStrCmpNICA									= NULL;
	f_HeapCreate								= NULL;
	f_vsnprintfA								= NULL;
	f_CreateThread								= NULL;
	f_VirtualFree								= NULL;
	f_InternetQueryOption						= NULL;
	f_FindResourceA								= NULL;
	f_LoadResource								= NULL;
	f_LockResource								= NULL;
	f_SizeofResource							= NULL;
	f_IsBadReadPtr								= NULL;
	f_CreateDirectoryA							= NULL;
	f_IsBadWritePtr								= NULL;
	f_CreateMutexA								= NULL;
	f_ReleaseMutex								= NULL;
	f_OpenMutexA								= NULL;
	f_WaitForSingleObject						= NULL;
	f_CreateEventA								= NULL;
	f_OpenEventA								= NULL;
	f_SetEvent									= NULL;
	f_DeleteFileA								= NULL;
	f_GetCommandLineA							= NULL;
	f_HeapSize									= NULL;
	f_TerminateThread							= NULL;
	f_DeleteCriticalSection						= NULL;
	f_SetFilePointer							= NULL;

	return;
}