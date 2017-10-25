#include <windows.h>

#include "id.h"

using namespace id_info;

DWORD id::get_dword(void) const
{
	if (IdElements->size() != 4) {
		return 0;
	}

	/*
	if (this->dword_value == 0) {
		DWORD tmp = 0;
		UINT c = 0;
		for (std::vector<BYTE>::iterator i = IdElements->begin(); i != IdElements->end(); i++, c++) {

			tmp = *i | tmp;

			if (c == (sizeof(DWORD) - 1)) {
				break;
			}

			tmp = tmp << 8;
		}

		this->dword_value = tmp;
	} */

	return this->dword_value;
}