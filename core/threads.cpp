#include "core/threads.h"
#include "debug/debug.h"

using namespace thread_space;

class threads {
private:

	bool			engine_state;

	DWORD			thread_state;
	UINT			thread_list[MAX_THREADS];
	UINT			thread_count;
	DWORD			thread_init_state;

public:
	// All of this is for internal use. Only call thread_switch()
	THREAD_ERROR thread_init(VOID);

	THREAD_ERROR thread_suspend_resume_threads(VOID);

	THREAD_ERROR thread_control(bool suspend, UINT thread_list[MAX_THREADS], PUINT thread_count);
};

threads *thread_data = NULL;

THREAD_ERROR thread_space::thread_switch(VOID)
{

#ifdef DEBUG_OUT
	DBGOUT("Thread switch");
#endif

	if (thread_data == NULL) {
		thread_data = (threads *)mem::malloc(sizeof(threads));
		thread_data->thread_init();
	}

	THREAD_ERROR status = thread_data->thread_suspend_resume_threads();

	return status;
}

THREAD_ERROR threads::thread_init(VOID)
{

	this->thread_state		= THREADS_RUNNING;
	this->thread_count		= 0;
	THREAD_ZEROMEM(this->thread_list, sizeof(this->thread_list));

	return THREAD_ERROR_OK;
}

THREAD_ERROR threads::thread_suspend_resume_threads(VOID)
{

	THREAD_ERROR status = (THREAD_ERROR)0;

	switch (this->thread_state) {
	case THREADS_RUNNING:
		// Suspend all threads

#ifdef DEBUG_OUT
		DBGOUT("threads: Suspending all threads");
#endif

		status = thread_control(TRUE, this->thread_list, &this->thread_count);
		if (status != ERROR_SUCCESS) 
			return THREAD_ERROR_FAIL;
		this->thread_state = THREADS_SUSPENDED;
		break;
	case THREADS_SUSPENDED:
		// Resume all threads

#ifdef DEBUG_OUT
		DBGOUT("threads: Resuming all threads");
#endif

		status = thread_control(FALSE, thread_list, &thread_count);
		if (status != ERROR_SUCCESS) 
			return FALSE;
		this->thread_state = THREADS_RUNNING;
		break;
	default:
		return THREAD_ERROR_FAIL;
	}

	return THREAD_ERROR_OK;
}

THREAD_ERROR threads::thread_control(bool suspend, UINT thread_list[MAX_THREADS], PUINT thread_count)
{
	HANDLE						snapshot, thread;
	DWORD						current_thread;
	DWORD						pid;
	THREADENTRY32				thread_entry32;

	pid							= THREAD_GETCURRENTPROCID();
	current_thread				= THREAD_GETCURRENTTHREADID();

	thread_entry32.dwSize		= sizeof(THREADENTRY32);
	snapshot 					= THREAD_GETSNAPSHOT(TH32CS_SNAPTHREAD, 0);

	if (snapshot == INVALID_HANDLE_VALUE) {
		return THREAD_ERROR_FAIL;
	}

	*thread_count = 0;

	if (THREAD_THREAD32FIRST(snapshot, &thread_entry32)) {
		while (TRUE) {

			if((thread_entry32.th32OwnerProcessID == pid) && (thread_entry32.th32ThreadID != current_thread)) {
				if (suspend == TRUE) {
					// Suspend threads
					thread_list[*thread_count] = thread_entry32.th32ThreadID;
					(*thread_count)++;
					
					thread = THREAD_OPENTHREAD(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
					if (thread == NULL) {
						return THREAD_ERROR_FAIL;
					}

					if (THREAD_SUSPENDTHREAD(thread) == -1) {
						return THREAD_ERROR_FAIL;
					}

					THREAD_CLOSEHANDLE(thread);
					thread = INVALID_HANDLE_VALUE;
				} else {
					// Resume threads
					thread = THREAD_OPENTHREAD(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
					if (thread == NULL) {
						return THREAD_ERROR_FAIL;
					}

					if (THREAD_RESUMETHREAD(thread) == -1) {
						return THREAD_ERROR_FAIL;
					}

					THREAD_CLOSEHANDLE(thread);
					thread = INVALID_HANDLE_VALUE;
				}
			}

			// Next thread
			if (THREAD_THREAD32NEXT(snapshot, &thread_entry32) == FALSE) break;
		}
	}
	return THREAD_ERROR_OK;
}

