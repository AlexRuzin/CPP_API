#include <Windows.h>

#pragma once

namespace error
{
#ifndef ERROR_CODE
#define ERROR_CODE UINT
#endif

#define ERROR_IF_NULL(x, y, z) if (x == NULL) { error::halt_dll(y, z); }
#define ERROR_IF_NOT_OK(x, y) if (x != error::ER_OK) { error::halt_dll(x, y); }

	enum {
		HALT_EXITPROCESS,
		HALT_SUSPENDALL,
		HALT_SLEEP
	};

	// Default exit code
	static DWORD default_halt_code = HALT_SLEEP;

	enum {
		ER_OK,
		ER_FAKE_TEST,
		ER_GENERAL_FAILURE,
		ER_THREAD_HALT_RESUME,
		ER_MEM_ALLOC_FAILURE,
		ER_CREATE_EVENT_FAILURE,
		ER_SVCHOST_RUNNING,						// we already have a hollowed SVCHOST
		ER_INJECT_FAILURE,
		ER_HEADER_ERROR,
		ER_NO_BROWSERS,
		ER_FS_READ,
		ER_HOLLOW_OK,
		ER_HOLLOW,
		ER_HOLLOW_PRETEST,
		ER_HOLLOW_CREATE_PROCESS,
		ER_HOLLOW_PE,
		ER_HOLLOW_ALLOC,
		ER_HOLLOW_WRITE,
		ER_HOLLOW_EP,
		ER_LOAD_DLL,
		ER_NSPR_HOOK,
		ER_FIND_NSPR_METHODS,
		ER_CONFIG_PARSER,
		ER_CONFIG_PARSER_DATA_BEFORE,
		ER_CONFIG_PARSER_DATA_AFTER,
		ER_CONFIG_PARSER_DATA_INJECT,
		ER_CORE_FIND_OPENTCPSOCKET,
		ER_SET_DYNAMIC_CONFIG,
		ER_WEB_CONFIG,
		ER_WININET_INIT,
		ER_WININET_SYNC,
		ER_WININET_PANIC,
		ER_INCORRECT_LOADED_DLL,				// for some reason, the DLL was injected into the wrong process.
		ER_GET_KERNEL32
	};

	// btc-qrab
	enum {
		ER_GET_PASS
	};

	VOID halt_dll(DWORD error_type, DWORD halt_code);
};