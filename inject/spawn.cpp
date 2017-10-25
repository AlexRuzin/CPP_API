#pragma once

#include <Windows.h>

#include <vector>

#include "api.h"

#include "spawn.h"
#include "debug/assert.h"

namespace spawn {
	PCRITICAL_SECTION sync_proc_list;
	bool engine_ok = false;
	Ptr<std::vector<spawn_process *>> SpawnedProcesses;
}

using namespace spawn;

void spawn::init(void)
{
	spawn::SpawnedProcesses = new std::vector<spawn_process *>();
	spawn::sync_proc_list = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
	cInitializeCriticalSection(sync_proc_list);

	engine_ok = true;
}

createprocess::createprocess(__in const mem::buffer2& raw_pe, __in const str_string& name)
{
	ASSERT(spawn::get_is_engine_ok() == true, "spawn: Engine not initialized");

	this->RawPE = new mem::buffer2(raw_pe.get_raw_buffer(), raw_pe.get_raw_size());
	this->process_handle = INVALID_HANDLE_VALUE;
	this->ModuleName = new str_string(name.to_lpstr());

	this->proc_info = (PPROCESS_INFORMATION)mem::malloc(sizeof(PROCESS_INFORMATION));
	this->startup_info = (STARTUPINFOA *)mem::malloc(sizeof(STARTUPINFOA));

	return;
}

bool createprocess::process(void)
{
	StrString FileName = new str_string(**this->ModuleName);
	FileName->add_to_prepend("C:\\Users\\dev\\Desktop\\bot_test\\");
	FileName->add_to_append(".exe");

#ifdef SPAWN_TEST
	MessageBoxA(NULL, **FileName, "Spawn: CreateProcess", MB_OK);
	return true;
#endif

	cDeleteFileA(FileName->to_lpstr());
	
	HANDLE file_handle = cCreateFileA(**FileName,
									GENERIC_WRITE | GENERIC_READ,
									0,
									NULL,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return false;
	}

	DWORD written = 0;
	BOOL write_status = 
		cWriteFile(file_handle, (LPCVOID)RawPE->get_raw_buffer(), RawPE->get_raw_size(), &written, NULL);
	if (write_status == FALSE) {
		return false;
	}

	cCloseHandle(file_handle);
											
	BOOL create_status = cCreateProcessA(		NULL,
												**FileName,
												NULL,
												NULL,
												FALSE,
												CREATE_NEW_CONSOLE,
												NULL,
												NULL,
												this->startup_info,
												this->proc_info);
	if (create_status == FALSE) {
		return false;
	}

	this->process_handle = this->proc_info->hProcess;

	return true;
}

bool spawn_process::kill_process(__inout HANDLE *proc_handle)
{
	BOOL term_status = TerminateProcess(*proc_handle, 0);
	if (term_status == FALSE) {
		return false;
	}

	*proc_handle = INVALID_HANDLE_VALUE;

	return true;
}