#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "spawn: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "spawn: Loading standard memory module (32)")
#endif
#endif

//#include "error.h"
#include "api.h"
#include "common/mem.h"
#include "common/fs.h"

#include "hollow.h"

//#define SPAWN_TEST //Does not create/hollow, just spawns a message box

#pragma once

namespace spawn {

	// Keep track of all instances
	class spawn_process;
	extern Ptr<std::vector<spawn_process *>> SpawnedProcesses;
	static std::vector<spawn_process *> *get_all_spawned_processes(void)
	{
		return SpawnedProcesses.get_value();
	}

	// Sync for spawn process list
	extern PCRITICAL_SECTION sync_proc_list;
	static void enter_sync(void)
	{
		cEnterCriticalSection(sync_proc_list);
	}

	static void leave_sync(void)
	{
		cLeaveCriticalSection(sync_proc_list);
	}

	// Initialize spawn namespace
	extern bool engine_ok;
	void init(void);
	static bool get_is_engine_ok(void)
	{
		return spawn::engine_ok;
	}

	// Spawn instances
	class spawn_process {
	protected:
		HANDLE		process_handle;
		Buffer2		RawPE;

	public:
		virtual bool process(void) = 0;

		virtual ~spawn_process(void)
		{

		}

		bool kill_process(__inout HANDLE *proc_handle);

		HANDLE get_proc_handle(void) const
		{
			return this->process_handle;
		}

		bool add_spawn_to_global(void)
		{
			spawn::get_all_spawned_processes()->push_back(this);

			return true;
		}
	};

	// Spawn by hollowing
	class hollow : public spawn_process {
	public:
		hollow(__in const mem::buffer2& raw_pe);

		virtual bool process(void);
	};

	// Spawn by injection
	class inject : public spawn_process {
	public:
		inject(__in const mem::buffer2& raw_pe);

		virtual bool process(void);
	};

	// Spawn by CreateProcess
	class createprocess : public spawn_process {
	private:
		StrString				ModuleName;
		PROCESS_INFORMATION		*proc_info;
		STARTUPINFOA			*startup_info;

	public:
		createprocess(__in const mem::buffer2& raw_pe, __in const str_string& name);

		virtual bool process(void);

		virtual ~createprocess(void)
		{
			mem::free(this->startup_info);
			mem::free(this->proc_info);
		}
	}; 

	static void destroy_all_spawned_processes(__in std::vector<spawn_process *> *procs)
	{

		for (std::vector<spawn_process *>::iterator i = procs->begin();
			i != procs->end(); i++)
		{
			HANDLE current_handle = (*i)->get_proc_handle();

			if (current_handle == INVALID_HANDLE_VALUE) {

			}

			(*i)->kill_process(&current_handle);
		}

		procs->clear();
	}
}