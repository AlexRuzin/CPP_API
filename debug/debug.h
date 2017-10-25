#pragma once

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "DEBUG MODE!")
#else 
#pragma message (OUTPUT_PRIMARY "DEBUG MODE!")
#endif
#endif

#define DEBUG_OUT
#define DEBUG_PRINTF

#if defined DEBUG_OUT
#ifdef DEBUG_PRINTF
#include <stdio.h>
#ifndef DISABLE_SECONDARY_OUTPUT
#pragma message (OUTPUT_PRIMARY "Debug is routed to printf!")
#endif
#define DBGOUT printf
#else
#define DBGOUT debug::debug_print
#ifndef DISABLE_SECONDARY_OUTPUT
#pragma message (OUTPUT_PRIMARY "Debug is routed to debugprint!")
#endif
#endif
#endif

#ifndef D
#define DP debug::debug_print
#define D printf
#endif	

#ifdef DEBUG_OUT
namespace debug
{
	//Ascii debug out
	VOID debug_print(LPCSTR FormatString, ...);
};
#endif