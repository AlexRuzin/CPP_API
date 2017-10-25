#include <Windows.h>

#include "../api.h"
#include "debug.h"

#pragma once

//#define ASSERT_TERMINATE
//#define ASSERT_NOTHING
#define ASSERT_SLEEP

#if defined(DEBUG_OUT)
#ifdef ASSERT_TERMINATE
#define ASSERT(expression, message) if (!(expression)) { MessageBoxA(NULL, message, "ASSERT", MB_OK); cExitProcess(0);}
#elif ASSERT_NOTHING
#define ASSERT(expression, message) if (!(expression)) { MessageBoxA(NULL, message, "ASSERT", MB_OK);}
#endif
#ifdef ASSERT_SLEEP
#define ASSERT(expression, message) if (!(expression)) { MessageBoxA(NULL, message, "ASSERT", MB_OK); cSleep(INFINITE);}
#endif
#endif