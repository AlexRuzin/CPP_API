#include <Windows.h>

#include "error.h"
#include "../api.h"
#include "debug.h"

VOID error::halt_dll(DWORD error_type, DWORD halt_code)
{

#ifdef DEBUG_OUT
	DBGOUT("error::halt_dll called with TYPE %08d, EXIT_CODE 0x%08x", error_type, halt_code);
#endif

	switch (halt_code)
	{
	case error::HALT_EXITPROCESS:
		cExitProcess(0);
	case error::HALT_SLEEP:
		cSleep(INFINITE);
	case error::HALT_SUSPENDALL:
		break;
	}
}