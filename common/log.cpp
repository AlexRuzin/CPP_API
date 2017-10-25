#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "log: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "log: Compiling 32-bit.")
#endif

//#include "phi.h"

#include "log.h"

#include "api.h"
#include "common/mem.h"
#include "debug/debug.h"

logger *default_log = NULL;

VOID log_tools::init(VOID)
{
	if (default_log == NULL) {
		default_log = (logger *)mem::malloc(sizeof(logger));
		default_log->init();
	}
}

VOID logger::init(VOID)
{
	this->is_active = true;
}

logger *get_default_log(VOID)
{
	if (default_log == NULL) {
		log_tools::init();
	}

	return default_log;
}

VOID logger::append_text(LPCSTR buffer, UINT length)
{
	if (buffer == NULL || length == 0) return;

#ifdef DEBUG_OUT
	DBGOUT("log: %s", buffer);
#endif

	// Get to the last LOG_ITEM
	PLOG_ITEM current_item = this->first_item;
	if (current_item == NULL) {
		this->first_item = current_item = (PLOG_ITEM)mem::malloc(sizeof(LOG_ITEM));
	} else {
		while (current_item->next != NULL) current_item = current_item->next;

		current_item->next = (PLOG_ITEM)mem::malloc(sizeof(LOG_ITEM));
		current_item = current_item->next;
	}

	current_item->buffer = (LPSTR)mem::malloc(length + str::ASCII_CHAR);
	current_item->size	= length;
	mem::copy(current_item->buffer, buffer, length);

	cGetSystemTime(&current_item->time);

	return;
}