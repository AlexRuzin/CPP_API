#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <time.h>

#include "core.h"

#include "api.h"
#include "common/str.h"
#include "common/mem.h"
#include "debug/debug.h"

//true: go ahead. false: there is an existing process
bool core::check_event_single(__in str_string *event_name)
{
	HANDLE existing_event = INVALID_HANDLE_VALUE;

	existing_event = cOpenEventA(EVENT_ALL_ACCESS, FALSE, event_name->to_lpstr());
	if (existing_event != NULL) {
		cCloseHandle(existing_event);
		return false;
	}

	return true;
}

bool core::set_event_single(__in str_string *event_name)
{
	HANDLE event_handle = INVALID_HANDLE_VALUE;

	event_handle = cCreateEventA(NULL, FALSE, TRUE, event_name->to_lpstr());
	if (event_handle == INVALID_HANDLE_VALUE) {
		return false;
	}

	core::handle_array.push_back(event_handle);

	return true;
}

// Always free this structure!!!
struct tm *core::get_timedata(void)
{
	errno_t	status = 0;
	struct tm* time_struct = (struct tm *)mem::malloc(sizeof(struct tm));
	time_t current_time = time(0);

	status = localtime_s(time_struct,  &current_time);
	if (!status) {
		mem::free(time_struct);
		return NULL;
	}

	return time_struct;
}

str_string *core::get_timestring(__in const struct tm *data)
{
	struct tm *current_data = NULL;
	if (data == NULL) {
		current_data = core::get_timedata();	
	} else {
		current_data = const_cast<struct tm *>(data);
	}

	LPSTR year = str::int_to_stringA(current_data->tm_year + 1900);
	LPSTR month = str::int_to_stringA(current_data->tm_mon + 1);
	LPSTR day = str::int_to_stringA(current_data->tm_mday);

	str_string *current_time = new str_string(year);
	current_time = *current_time + "-";
	current_time = *current_time + month;
	current_time = *current_time + "-";
	current_time = *current_time + day;
				
	mem::free(year);
	mem::free(month);
	mem::free(day);

	mem::free(current_data);

	return current_time;
}

void exit_process(__in const time_t timeout)
{	

#ifdef DEBUG_OUT
	DBGOUT("[!] Exiting process in %d seconds....\n\n", (UINT)timeout);
#endif		  


#ifdef DO_NOT_EXIT_AFTER_FAILURE
	DBGOUT("\n\n\t\tPress any key to exit...\n\n");
	_getch();
	cExitProcess(0);
#else
	cSleep((DWORD_PTR)timeout);
	cExitProcess(0);
#endif
}

void exit_process(__in const time_t timeout, __inopt const LPSTR message)
{

#ifdef DEBUG_OUT
	if (message == NULL) {
		DBGOUT("[!] Exiting process in %d seconds (%s)....\n\n", (UINT)timeout, message);
	} else {
		 DBGOUT("[!] Exiting process in %d seconds (%s).....\n\n", (UINT)timeout, message);
	}
#endif

#ifdef DO_NOT_EXIT_AFTER_FAILURE
	DBGOUT("\n\n\t\tPress any key to exit...\n\n");
	_getch();
	cExitProcess(0);
#else
	cSleep((DWORD_PTR)timeout);
	cExitProcess(0);
#endif
}

void exit_thread(__in const time_t timeout, __inopt const str_string& message) 
{

#ifdef DEBUG_OUT
	DBGOUT("[!] Exiting thread in %d seconds (%s).....\n\n", (UINT)timeout, **message);		 
#endif

#ifdef DO_NOT_EXIT_AFTER_FAILURE
	DBGOUT("\n\n\t\tPress any key to exit...\n\n");
	_getch();
	cExitProcess(0);
#else
	cSleep((DWORD_PTR)timeout);
	cExitProcess(0);
#endif

	ExitThread(0);   
}


