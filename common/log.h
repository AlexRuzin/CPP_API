#include <Windows.h>
#include "../../_api/common/str.h"

#pragma once

namespace log_tools {
	typedef struct {
		LPSTR			raw_data;
		UINT			raw_data_size;
		str::PLINE		first_line;
	} LOG_ENTRY, *PLOG_ENTRY; 

	typedef struct log_item {
		LPSTR			buffer;
		UINT			size;

		SYSTEMTIME		time;

		log_item		*next;
	} LOG_ITEM, *PLOG_ITEM;

	// Initializes the logger class
	VOID init(VOID);

};

using namespace log_tools;

class logger {
	bool		is_active;
	PLOG_ITEM	first_item;

public:
	VOID init(VOID);
	VOID logger::append_text(LPCSTR buffer, UINT length);

};

logger *get_default_log(VOID);