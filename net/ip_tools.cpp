#include <Windows.h>

#include "ip_tools.h"
#include "../../_api/common/mem.h"
#include "../../_api/common/str.h"

using namespace ip_tools;

bool ip_tools::is_ip(__in LPCSTR name)
{
	IP_ADDR_A address;
	mem::zeromem(&address, sizeof(IP_ADDR_A));
	PCHAR ptr = (PCHAR)name;
	for (UINT i = 0; i <= 3; i++) {
		PCHAR end = ptr;
		while (*end != '.') {
			if (*end == '\0') {
				if (i == 3) {
					break;
				}
				i = 0;
				while (address.octets[i] != NULL) {
					mem::free(address.octets[i]);
					i++;
				}
				return false;
			}
			end++;
		}
		address.octets[i] = (PCHAR)mem::malloc((DWORD_PTR)end - (DWORD_PTR)ptr + str::ASCII_CHAR);
		mem::copy(address.octets[i], ptr, (DWORD_PTR)((DWORD_PTR)end - (DWORD_PTR)ptr));
		if (*end == '\0') break;
		ptr = &end[str::ASCII_CHAR];
	}

	for (UINT i = 0; i < 4; i++) {
		if (str::is_digitA(address.octets[i], str::lenA(address.octets[i])) == false) {
			for (i = 0; i < 4; i++) {
				mem::free(address.octets[i]);
			}
			return false;
		}
	}

	for (UINT i = 0; i < 4; i++) {
		mem::free(address.octets[i]);
	}

	return true;
}