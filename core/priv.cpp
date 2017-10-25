#include <Windows.h>

#include "priv.h"

#include "api.h"
#include "common/mem.h"

using namespace priv;

bool priv::init(types::DEFAULT_NO_PARAMETERS)
{

	HANDLE token = INVALID_HANDLE_VALUE;
	BOOL open_token_status = OpenProcessToken(cGetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&token);
	if (open_token_status != TRUE) {
		return false;
	}

	LUID luid;
	BOOL lookup_status = LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid);
	if (lookup_status != TRUE) {
		cCloseHandle(token);
		return FALSE;
	}

	TOKEN_PRIVILEGES privileges;
	mem::zeromem(&privileges, sizeof(TOKEN_PRIVILEGES));
	privileges.PrivilegeCount				= 1;
	privileges.Privileges[0].Luid			= luid;
	privileges.Privileges[0].Attributes		= SE_PRIVILEGE_ENABLED;
	BOOL adjust_status = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (adjust_status != TRUE) {
		cCloseHandle(token);
		return false;
	}

	cCloseHandle(token);
	return true;
}