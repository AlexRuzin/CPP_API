#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "Registry API Loaded.")
#else 
#pragma message (OUTPUT_PRIMARY "Registry API Loaded.")
#endif

#include "reg.h"
#include "debug/error.h"
//#include "../_api/common/mem.h"
#include "common/str.h"

using namespace reg;

bool reg::create_reg_string(	HKEY		hive,
								LPCSTR		subkey,
								LPCSTR		key_name,
								LPCSTR		value)
{

	HKEY hive_handle;
	ERROR_CODE reg_status = RegOpenKeyExA(	hive,
											NULL,
											0,
											KEY_WRITE,
											&hive_handle);
	if (reg_status != ERROR_SUCCESS) {
		return false;
	}

	HKEY key_handle;
	reg_status = RegCreateKeyExA(	hive_handle,
									subkey,
									0,
									NULL,
									0,
									KEY_WRITE,
									NULL,
									&key_handle,
									NULL);
	if (reg_status != ERROR_SUCCESS) { 
		RegCloseKey(hive_handle);
		return false;
	}

	RegSetValueExA(	key_handle,
					key_name,
					0,
					REG_SZ,
					(const BYTE *)value,
					str::lenA(value) + str::ASCII_CHAR);

	RegCloseKey(key_handle);
	RegCloseKey(hive_handle);

	return true;
}