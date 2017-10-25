#pragma once

#include <ctime>

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#undef CONFIG_OK
#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#ifndef DISABLE_LIBRARY_INFO
#pragma message ("Using 64-bit types")
#else 
#pragma message ("Using 32-bit types")
#endif
#endif

#define __interface__ __cdecl

// Debug types
#ifndef CONFIG_COMPILE64

#undef BREAK
#ifndef BREAK
#define BREAK __asm{int 3}
#endif

#undef NOP
#ifndef NOP
#define NOP __asm{nop};
#endif

#endif

// Annotations
#define __in_free __in // The class will free the parameter once the deconstructor is called



namespace types {
	typedef DWORD	OFFSET32;
	static const UINT offset_zero = 0;

	typedef DWORD	ORDINAL32;

	static const	DWORD PAGE_SIZE = 0x1000;

	typedef UINT	TIME32;
	
	typedef void	CORE_ENTRY_POINT;
	typedef UINT	CORE_ENTRY_POINT_INTEGER;

	// Defines entry point datatypes
	typedef INT		ENTRY_POINT;
#define __oep_conv	_cdecl
	typedef VOID	DEFAULT_NO_PARAMETERS;

	// Return types
	typedef VOID	NO_RETURN_VALUE;

	// Export types
#define __oep_export_conv __declspec(dllexport)
};
