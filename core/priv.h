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

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "priv: 64")
#else 
#pragma message (OUTPUT_PRIMARY "priv: 32")
#endif

namespace priv {

	// Install priv
	bool init(types::DEFAULT_NO_PARAMETERS);

}