#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "IP Tools: Ready")
#else 
#pragma message (OUTPUT_PRIMARY "IP Tools: Ready")
#endif


namespace ip_tools {
	// Returns true if the buffer is an ip address
	typedef struct {
		PCHAR octets[4];
	} IP_ADDR_A, *PIP_ADDR_A;
	bool is_ip(__in LPCSTR name);
};