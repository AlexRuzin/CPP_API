// mem::free does not release ALLOC_INFO!!!
// mem::size uses HeapFree instead of cHeapFree

#include <Windows.h>

#include "api.h"
#include "common/mem.h"
#include "core/threads.h"


#include "debug/assert.h"
#include "debug/error.h"
#include "debug/debug.h"

#ifdef LOG_ALLOCS
mem::PALLOC_INFO log_array_start		= NULL;
mem::PALLOC_INFO log_array_current		= NULL;
#endif

// The private heap handle
static HANDLE private_heap = INVALID_HANDLE_VALUE;

VOID mem::init(VOID)
{

	private_heap		= INVALID_HANDLE_VALUE;

	// Initialize the log array

#ifdef LOG_ALLOCS
	if (log_array_start == NULL) {
		log_array_start = (PALLOC_INFO)cHeapAlloc(mem::getlocalheap(), 0, sizeof(ALLOC_INFO));
		mem::zeromem(log_array_start, sizeof(ALLOC_INFO));
		log_array_current = NULL;
	} 
#endif

	return;
}

VOID mem::zeromem(LPVOID mem, UINT size)
{
	PBYTE ptr	= (PBYTE)mem;
	UINT i		= 0;

	while (i < size) {
		*ptr = 0;
		ptr++;
		i++;
	}

	return;
}

HANDLE mem::getlocalheap(VOID)
{

	if (private_heap == INVALID_HANDLE_VALUE) {
		private_heap = cGetProcessHeap();//cHeapCreate(0, 0x1000, 0);
		if (private_heap == NULL) {
			error::halt_dll(error::ER_MEM_ALLOC_FAILURE, error::default_halt_code);
		}
	}

	return private_heap;
}

LPVOID mem::malloc(SIZE_T size)
{
	if (size == 0) return NULL;

	LPVOID			buffer = cHeapAlloc(mem::getlocalheap(), 0, size);
	if (buffer == NULL) {
		error::halt_dll(error::ER_MEM_ALLOC_FAILURE, error::default_halt_code);
		return NULL;
	} 

	mem::zeromem(buffer, size);
#ifdef LOG_ALLOCS
	mem::add_alloc_element(buffer, size);
#endif

	return buffer;
}

LPVOID mem::malloc_and_copy(__in const SIZE_T size, __in const LPVOID buffer)
{
	if (size == 0) return NULL;

	LPVOID buffer_new = (LPVOID)mem::malloc(size);
	mem::copy(buffer_new, buffer, size);

	return buffer_new;
}

UINT mem::size(LPCVOID mem)
{
	return (UINT)HeapSize(mem::getlocalheap(), 0, mem);
}

// copy_data: true: copies data from old buffer into new buffer (assuming size is big enough. 
//			if it isn't, nothing is done). deallocates old_buffer
//			false: does not copy, but deallocates old_buffer
LPVOID mem::realloc(LPVOID old_buffer, UINT new_buffer_size, bool copy_data)
{
	LPVOID new_buffer = (LPVOID)mem::malloc(new_buffer_size);
	mem::size(new_buffer);
	if (copy_data == true && (new_buffer_size >= mem::size(old_buffer))) {
		mem::copy(new_buffer, old_buffer, mem::size(old_buffer));
	}

	mem::free(old_buffer);
	return new_buffer;
}

#ifdef LOG_ALLOCS
VOID mem::add_alloc_element(LPVOID buffer, UINT size) 
{
	if (log_array_current == NULL) {
		log_array_current = log_array_start;
		log_array_current->buffer = buffer;
		log_array_current->buffer_size = size;
		return;
	}

	log_array_current->next			= (PALLOC_INFO)cHeapAlloc(mem::getlocalheap(), 0, size);
	mem::zeromem(log_array_current->next, sizeof(ALLOC_INFO));
	log_array_current				= log_array_current->next;
	log_array_current->buffer		= buffer;
	log_array_current->buffer_size	= size;

	return;
}
#endif

VOID mem::free(LPVOID buffer)
{
	if (buffer == NULL) return;

	cHeapFree(mem::getlocalheap(), 0, buffer);
	return;
}

VOID mem::free_and_null(LPVOID *buffer)
{
	cHeapFree(mem::getlocalheap(), 0, *buffer);
	*buffer = NULL;
}

VOID mem::copy(LPVOID dest, LPCVOID src, UINT size)
{
	if (dest == NULL || src == NULL || size == 0) {
		DebugBreak();
	}

	for (UINT i = 0; i < size; i++) {
		*(PBYTE)((DWORD_PTR)dest + i) = *(PBYTE)((DWORD_PTR)src + i);
	}

	return;
}

bool mem::compare(LPCVOID a, LPCVOID b, UINT size)
{
	if (a == NULL || b == NULL || size == 0) return false;

	for (UINT i = 0; i < size; i++) {
		if (*(PBYTE)((DWORD_PTR)a + i) != *(PBYTE)(((DWORD_PTR)b + i))) {
			return true;
		}
	}

	return false;
}

bool mem::is_object_zero(LPCVOID buffer, UINT buffer_size)
{
	if (buffer == NULL || buffer_size == 0) return false;

	PBYTE ptr = (PBYTE)buffer;
	for (UINT i = 0; i < buffer_size; i++) {
		if (ptr[i] == 0) return false;
	}

	return true;
}

VOID mem::set(LPVOID buffer, BYTE value, UINT size)
{
	PBYTE ptr = (PBYTE)buffer;
	for (UINT i = 0; i < size; i++) {
		ptr[i] = value;
	}

	return;
}

// note: sequence_size must be greater than sizeof(DWORD)
LPVOID mem::scan_memory(DWORD_PTR start, DWORD_PTR end, PBYTE sequence, UINT sequence_size)
{

/*
SIZE_T WINAPI VirtualQuery(
  _In_opt_  LPCVOID lpAddress,
  _Out_     PMEMORY_BASIC_INFORMATION lpBuffer,
  _In_      SIZE_T dwLength
);
*/
	if (start == end || sequence == NULL || sequence_size < sizeof(DWORD)) return NULL;

	LPVOID current_base = (LPVOID)start;
	while ((DWORD_PTR)current_base < end) {
		MEMORY_BASIC_INFORMATION mem_info;
		mem::zeromem(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
		//PMEMORY_BASIC_INFORMATION mem_info = (PMEMORY_BASIC_INFORMATION)mem::malloc(sizeof(MEMORY_BASIC_INFORMATION));
		SIZE_T query_status = cVirtualQuery(current_base, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
		if (query_status != sizeof(MEMORY_BASIC_INFORMATION)) return NULL;

		if (mem_info.State != MEM_COMMIT) {
			current_base = (LPVOID)((DWORD_PTR)current_base + mem_info.RegionSize);
			continue;
		}

		// Scan region
		PBYTE ptr = (PBYTE)current_base;
		while ((DWORD)((DWORD)((DWORD_PTR)ptr - (DWORD_PTR)current_base) + sequence_size) <= mem_info.RegionSize) {

			// Check first byte
			if (*(PDWORD)ptr != *(PDWORD)sequence) {
				ptr++;
				continue;
			}

			if (sequence_size == sizeof(DWORD)) return (LPVOID)ptr;

			UINT i = 0;
			for (; i < sequence_size; i++) {
				if (*(PBYTE)((DWORD_PTR)ptr + i) != *(PBYTE)((DWORD_PTR)sequence + i)) break;
			}
			if (i == sequence_size) {
				return (LPVOID)ptr;
			}

			ptr++;
		}

		current_base = (LPVOID)((DWORD_PTR)current_base + mem_info.RegionSize);
	}

	return NULL;
}

bool page_state_sync_init = false;
CRITICAL_SECTION page_state_sync;
mem::ERROR_MEM_PAGE mem::set_page_permissions(mem::PMEM_PAGE_STATE page_state, MEM_STATE new_state)
{
	// Check for r on page
	if (page_state == NULL || cIsBadReadPtr(page_state->address, sizeof(DWORD))) return mem::ER_MEM_PAGE_GENERAL_FAILURE;

	if (page_state_sync_init == false) {
		cInitializeCriticalSection(&page_state_sync);
		MEM_PAGE_SYNC_ENTER(&page_state_sync);
	}

#ifndef DISABLE_THREADING
	thread_space::thread_switch();
#endif

	PMEMORY_BASIC_INFORMATION mem_info = (PMEMORY_BASIC_INFORMATION)mem::malloc(sizeof(MEMORY_BASIC_INFORMATION));
	MEM_ERROR mem_status = (MEM_ERROR)cVirtualQuery((LPCVOID)page_state->address, mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	if ((UINT)mem_status != sizeof(MEMORY_BASIC_INFORMATION)) {
#ifndef DISABLE_THREADING
		thread_space::thread_switch();
#endif
		mem::free(mem_info);
		MEM_PAGE_SYNC_LEAVE(&page_state_sync);
		return mem::ER_MEM_PAGE_GENERAL_FAILURE;
	}

	switch (new_state) {
	case mem::MEM_STATE_RWX:
		mem_status = (MEM_ERROR)cVirtualProtect(	(LPVOID)mem_info->BaseAddress,
													mem_info->RegionSize,
													PAGE_EXECUTE_READWRITE,
													&(page_state->old_protect));
		if (!mem_status) {
			mem::free(mem_info);
			MEM_PAGE_SYNC_LEAVE(&page_state_sync);
			return mem::ER_MEM_PAGE_GENERAL_FAILURE;
		}
		page_state->state = MEM_STATE_RWX;
		break;
	case mem::MEM_STATE_RX:
		DWORD junk;
		mem_status = (MEM_ERROR)cVirtualProtect(	(LPVOID)mem_info->BaseAddress,
													mem_info->RegionSize,
													page_state->old_protect,
													&junk);
		if (!mem_status) {
			mem::free(mem_info);
			MEM_PAGE_SYNC_LEAVE(&page_state_sync);
			return mem::ER_MEM_PAGE_GENERAL_FAILURE;
		}
		page_state->state = MEM_STATE_RX;
		break;
	default:
#ifndef DISABLE_THREADING
		thread_space::thread_switch();
#endif
		mem::free(mem_info);
		MEM_PAGE_SYNC_LEAVE(&page_state_sync);
		return mem::ER_MEM_PAGE_GENERAL_FAILURE;
	}

#ifndef DISABLE_THREADING
	thread_space::thread_switch();
#endif

	mem::free(mem_info);
	MEM_PAGE_SYNC_LEAVE(&page_state_sync);
	return mem::ER_MEM_PAGE_OK;
}

mem::ER_MEM_INFO mem::get_memory_info(__out mem_info **info)
{
	*info = new mem_info(true);

	return ER_STAT_OK;
}

LPVOID mem::valloc(__in const UINT min_size, __in const mem::PAGE_PERMISSIONS access)
{
	DWORD total_size = ROUND_BY_PAGE(min_size);
	if (total_size == 0) {
		return NULL;
	}

	return cVirtualAlloc(NULL, (UINT)total_size, mem::default_alloc, (DWORD)access);
}

bool mem::vfree(__in const mem::PAGE_BASE base, __in const UINT min_size)
{
	DWORD total_size = ROUND_BY_PAGE(min_page);
	if (total_size == 0 || base == NULL) {
		return false;
	}

	BOOL return_status = cVirtualFree((LPVOID)base, total_size, mem::default_dealloc);
	if (return_status) {
		return true;
	} else {
		return false;
	}
}

#ifdef USE_CUSTOM_ALLOCATOR
void *operator new(__in const std::size_t length)
{
	void *_allocated = (void *)mem::malloc((SIZE_T)length);
	ASSERT(_allocated != NULL, "Failed to allocate memory!");

	

	return _allocated;
}
#endif

bool mem::shift_bytes_at_beg(__inout LPVOID buffer, 
						__in const UINT buffer_len,
						__in const UINT shift_by)
{	   
	if (shift_by >= buffer_len) {
		return false;
	}


	PBYTE ptr = (PBYTE)mem::malloc(buffer_len);
	PBYTE src = (PBYTE)buffer;

	UINT data_to_move = buffer_len - shift_by;
	for (UINT i = shift_by; i < buffer_len; i++) {
		ptr[i] = src[i];
	}


	return true;
}

bool mem::buffer2::append(__in const mem::buffer2& buffer_in)
{					  
	LPVOID current_buffer = (LPVOID)this->buffer;
	this->buffer = (LPVOID)mem::malloc(this->buffer_size + buffer_in.get_raw_size());
	
	mem::copy(this->buffer, current_buffer, this->buffer_size);
	mem::copy((LPVOID)((DWORD_PTR)this->buffer + this->buffer_size), *buffer_in, buffer_in.get_raw_size());
	this->buffer_size += buffer_in.get_raw_size();	

#ifndef DISABLE_BUFFER2_VECTORED
	UINT new_buffer_size = buffer_in.get_raw_size();
	if (Elements->size() != 0) {
		PBYTE ptr = (PBYTE)*buffer_in;
		for (UINT c = 0; c < new_buffer_size; c++) {
			Elements->push_back(*(PBYTE)&ptr[c]);
		}
	} else {
		return false;
	}
#endif

	return true;
}