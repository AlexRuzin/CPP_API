#include <Windows.h>

#include <vector>
#include <memory>

#include "sync.h"

#include "api.h"

using namespace sync;

// Critical section
critical_section::critical_section(types::DEFAULT_NO_PARAMETERS)
{
	this->sync_object = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
	cInitializeCriticalSection(this->sync_object);

	this->object_ok = true;

	return;
}

critical_section::~critical_section(void)
{
	if (this->sync_object != NULL) {
		mem::free_and_null((LPVOID *)this->sync_object);
	}
}

void critical_section::sync_enter(void) const
{
	ASSERT(this->get_is_ok() != false, "sync: Invalid sync object");

	cEnterCriticalSection(this->sync_object);

	return;
}

void critical_section::sync_leave(void) const
{
	ASSERT(this->get_is_ok() != false, "sync: Invalid sync object");

	cLeaveCriticalSection(this->sync_object);
	return;
}

PCRITICAL_SECTION critical_section::get_critical_section(void) const
{
	return this->sync_object;
}
