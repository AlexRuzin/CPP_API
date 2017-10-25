#include <Windows.h>

namespace loader {

	// Checks header sanity
	bool check_pe_headers(LPVOID raw_pe, UINT raw_pe_size);

	// Loads into virtual space
	LPTHREAD_START_ROUTINE load_raw_into_virtual(LPVOID raw, UINT raw_size);

	// Resolves IAT
	VOID resolve_iat(LPVOID virtual_base);
};