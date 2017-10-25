#pragma once

#ifndef CONFIG_OK
#include "../config.h"
#endif

#include <Windows.h>

#include <vector>

#ifdef DO_NOT_EXIT_AFTER_FAILURE
#ifndef DISABLE_SECONDARY_OUTPUT
#pragma message (OUTPUT_PRIMARY "WARNING: Program will not terminate after EXIT(x)")
#endif
#endif

#include "common/str.h"

//void core::exit_process(__in const time_t timeout);
#define EXIT exit_process
void exit_process(__in const time_t timeout, __inopt const str_string& message);
void exit_process(__in const time_t timeout);
void exit_process(__in const time_t timeout, __inopt const LPSTR message);

#define EXITTHREAD exit_thread
void exit_thread(__in const time_t timeout, __inopt const str_string *message);

namespace core {
	// Prevents multiple instances from running at the same time
	bool check_event_single(__in str_string *event_name);

	static std::vector<HANDLE> handle_array;
	bool set_event_single(__in str_string *event_name);

	// Datetime
	//typedef str_string *time_string;
	//typedef struct tm *timedata;
	struct tm *get_timedata(void);

	str_string *get_timestring(__in const struct tm *data);

};

