#include <Windows.h>

namespace reg {
	bool create_reg_string(	HKEY		hive,
							LPCSTR		subkey,
							LPCSTR		key_name,
							LPCSTR		value);
};