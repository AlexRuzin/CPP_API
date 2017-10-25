#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#ifdef USE_PE32
#error "USE_PE32 already defined"
#endif
#define USE_PE32

#include <stdio.h>
#include <psapi.h>

#include <vector>
#include <memory>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "mem: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "mem: Loading standard memory module (32)")
#endif
#endif

// Logs all memory allocations
//#define LOG_ALLOCS
#ifdef LOG_ALLOCS
#define LOG_ARRAY_SIZE 4
#else
#define LOG_ARRAY_SIZE 0
#endif

#pragma comment (lib, "Psapi.lib")

#define DISABLE_BUFFER2_VECTORED
#ifndef DISABLE_SECONDARY_OUTPUT
#ifdef DISABLE_BUFFER2_VECTORED
#pragma message (OUTPUT_PRIMARY "mem: buffer2: Disabling vectored defaults")
#endif
#endif

// Page allocation config
#define DEFAULT_PAGE_SIZE				0x1000
#define DEFAULT_PAGE_ALLOC_FLAGS		MEM_RESERVE | MEM_COMMIT
#define DEFAULT_PAGE_DEALLOC_FLAGS		MEM_DECOMMIT		

//#define DISABLE_BUFFER2_COPY_CONSTRUCTOR
#ifndef DISABLE_BUFFER2_COPY_CONSTRUCTOR
#pragma warning(disable: 4521)
#endif

// Use custom allocator
#ifdef CONFIG_USE_CUSTOM_NEW
#define USE_CUSTOM_ALLOCATOR
#ifndef DISABLE_LIBRARY_INFO
#pragma message(OUTPUT_PRIMARY "mem: Using custom allocator!")
#endif
#endif

// Smart Pointer //////////////////////////////////////////////////////////////
template <typename T>
class Ptr {
private:
	T*				ptr;

	class counter;
	friend class counter;
	counter			*reference_count;

	static const UINT one_reference		= 1;
	static const UINT null_reference	= 0;
	static const UINT error_reference	= -1;
	class Ptr;

	class counter {
		friend class Ptr;

	private:
		UINT				raw;
		
	public:
		counter(VOID) :
			raw(one_reference),
			{
				//pointed_by->push_back(o);
			}
		counter(__in const UINT input) :
			raw(input)
			{
			}
		~counter(VOID)
			{
			}

		// Counter operators
		UINT operator++(VOID) 
		{
			return (++raw);
		}

		UINT operator--(VOID)
		{
			return (--raw);
		}

		VOID set_value(__in const UINT i)
		{
			this->raw = i;
			return;
		}

		UINT get_value(VOID) const
		{
			return raw;
		}

		const UINT operator*(void)
		{
			return raw;
		}
	};

public:
	Ptr(VOID) :
		ptr(NULL),
		reference_count(NULL)
		{
			reference_count = new counter(null_reference);
		}

	Ptr(T* raw) :
		ptr(raw),
		reference_count(NULL)
		{
			if (raw != NULL) {
				this->reference_count = new counter(one_reference);
			} else {
				this->reference_count = new counter(null_reference);
			}
		}

	// Copying from another Ptr
	Ptr(const Ptr<T>& o) :
		ptr(o.ptr),
		reference_count(o.reference_count)
		{
			reference_count++;
		}

	~Ptr(VOID)
	{
		if (reference_count != NULL) {
			delete reference_count;
			reference_count = NULL;
		}
		
		if (ptr != NULL) {
			delete ptr;
			ptr = NULL;
		}
	}


	// References
	T& operator*(VOID) const
	{
		return *ptr;
	}

	T* operator->(VOID) const
	{
		return ptr;
	}

	bool operator!=(T* o) const
	{
		if (o == ptr) {
			return false;
		}

		return true;
	}

	// Assignment to another Ptr
	Ptr<T>& operator=(Ptr<T>& o)
	{
		if (this == &o) {
			return *this;
		}

		if (--*reference_count == 0) {
			delete ptr;
			delete reference_count;
		}

		ptr				= o.ptr;
		reference_count = o.reference_count;
		++*reference_count;

		return *this;
	}

	// Assignment to another object
	Ptr<T>& operator=(const T* o)
	{
		if (o == NULL) {
			reference_count->set_value(0);
			if (reference_count == 0) {
				delete ptr;
			} else if (reference_count->get_value() == error_reference) {
				// Initialized as a null pointer. 
				reference_count->set_value(one_reference);
				ptr = (T*)o;

				return *this;
			} 
			reference_count = new counter(null_reference);
			ptr = (T*)NULL;

			return *this;
		}

		if (ptr == o) {
			return *this;
		}

		if (--*reference_count == 0) {
			delete ptr;
			delete reference_count;
		} else if (reference_count->get_value() == error_reference) {
			// Initialized as a null pointer. 
			reference_count->set_value(one_reference);
			ptr = (T*)o;

			return *this;
		} 

		reference_count = new counter(one_reference);
		ptr = (T*)o;	
		
		return *this;
	}

	// Comparisons. Pointer == value
	bool operator==(const T* o) const
	{
		if (ptr == o) {
			return true;
		} 

		return false;
	}

	// Clear all data. Includes all other pointers being pointed to
	VOID Ptr::clear_(__inout Ptr *o)
	{
		delete ptr;
		ptr = NULL;

		reference_count->set_value(null_reference);

		*o = NULL;

		return;
	}

	VOID Ptr::clear(VOID)
	{
		delete ptr;

		reference_count->set_value(null_reference);

		ptr = NULL;

		return;
	}

	VOID Ptr::free(VOID) 
	{
		mem::free(ptr);
		ptr = NULL;

		this->reference_count->set_value(null_reference);
	}

	T *Ptr::get_value(void) const
	{
		return this->ptr;
	}

	T &Ptr::get_ref(void) const
	{
		return *this->ptr;
	}

	bool get_is_null(VOID) const
	{
		if (this->ptr == NULL) {
			return true;
		} else {
			return false;
		}
	}

	void Ptr::set_value(T* o)
	{
		ptr = o;
	}
};

namespace mem
{
	typedef DWORD MEM_ERROR;
	enum {
		MEM_ER_OK,
		MEM_ER_GENERAL_FAILURE
	};

	// Keeps a logged array of buffers that exist
	static const UINT log_array_size = LOG_ARRAY_SIZE;
	typedef struct alloc_info {
		PVOID		buffer;
		UINT		buffer_size;
		alloc_info	*next;
	} ALLOC_INFO, *PALLOC_INFO;

	// Adds an ALLOC_INFO element
	VOID add_alloc_element(LPVOID buffer, UINT size);

	// Page allocation
	class page;
	typedef DWORD PAGE_PERMISSIONS;
	typedef DWORD PAGE_BASE;
	static const DWORD default_alloc	= DEFAULT_PAGE_ALLOC_FLAGS;
	static const DWORD default_dealloc	= DEFAULT_PAGE_DEALLOC_FLAGS;
	static const UINT default_page_size	= DEFAULT_PAGE_SIZE;
	LPVOID valloc(__in const UINT min_size, __in const PAGE_PERMISSIONS access);
	bool vfree(__in const PAGE_BASE base, __in const UINT min_size);
#define ROUND_UP(value, rounding)		(((value) + ((rounding) - 1)) & (~((rounding) - 1)))
#define ROUND_BY_PAGE(value)			ROUND_UP(value, mem::default_page_size)
	class page {
	private:
		PAGE_BASE		page_base;
		UINT			allocated_size;

	public:
		page(__in const UINT min_size) :
			allocated_size(ROUND_BY_PAGE(min_size)),
			page_base(NULL)
		{
			page_base = (mem::PAGE_BASE)mem::valloc(
				this->allocated_size, PAGE_EXECUTE_READWRITE);
			if (page_base == NULL) {
				return;
			}
		}

		~page(types::DEFAULT_NO_PARAMETERS)
		{
			if (page_base != NULL) {
				mem::vfree((mem::PAGE_BASE)page_base, allocated_size);
			}
		}

		LPVOID get_base(types::DEFAULT_NO_PARAMETERS) const
		{
			return (LPVOID)this->page_base;
		}

		UINT get_rounded_size(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->allocated_size;
		}
	};

	// Scans memory for a sequence
	static const DWORD virtual_base		= 0;
	static const DWORD max_page			= 0xffffffff;
	static const DWORD min_page			= 0x00010000;
	static const DWORD page_dll_low		= 0x7ffeffff;
	static const DWORD page_dll_high	= 0x7ffffffe;
	LPVOID scan_memory(DWORD_PTR start, DWORD_PTR end, PBYTE sequence, UINT sequence_size);

	// Initializes the memory module
	VOID init(VOID);

	// Zero memory function
	VOID zeromem(LPVOID mem, UINT size);

	// Returns the DLL's private heap
	HANDLE getlocalheap(VOID);

	// Malloc
	LPVOID malloc(SIZE_T size);

	LPVOID malloc_and_copy(__in const SIZE_T size, __in const LPVOID buffer);

	// Returns a heap element size
	UINT size(LPCVOID mem);

	// Realloc. Frees old_buffer, creates a new buffer of specified size
	LPVOID realloc(LPVOID old_buffer, UINT new_buffer_size, bool copy_data);

	// Frees a buffer
	VOID free(LPVOID buffer);

	// Frees a buffer, makes pointer NULL
	VOID free_and_null(LPVOID *buffer);

	// Copies memory
	VOID copy(LPVOID dest, LPCVOID src, UINT size);

	// Compares two memory regions
	bool compare(LPCVOID a, LPCVOID b, UINT size);

	// Returns a true if all bytes of the object are 0
	bool is_object_zero(LPCVOID buffer, UINT buffer_size);

	// Shifts the bytes of a buffer from the beginning, leaving zeros at the front
	bool shift_bytes_at_beg(__inout LPVOID buffer, 
		__in const UINT buffer_len,
		__in const UINT shift_by);

	// Setting page permissions
	typedef DWORD ERROR_MEM_PAGE;
	enum {
		ER_MEM_PAGE_OK,
		ER_MEM_PAGE_GENERAL_FAILURE
	};
#define MEM_PAGE_SYNC_ENTER(x) cEnterCriticalSection(x)
#define MEM_PAGE_SYNC_LEAVE(x) cLeaveCriticalSection(x)
	typedef DWORD MEM_STATE;
	enum {
		MEM_STATE_RWX,
		MEM_STATE_RX
	};
	typedef struct {
		LPCVOID					address;
		MEM_STATE				state;
		DWORD					old_protect;
	} MEM_PAGE_STATE, *PMEM_PAGE_STATE;
	ERROR_MEM_PAGE set_page_permissions(mem::PMEM_PAGE_STATE page_state, MEM_STATE new_state);

	// memset
	VOID set(LPVOID buffer, BYTE value, UINT size);

	// Memory info class
	class mem_info;
	typedef DWORD ER_MEM_INFO;
	enum {
		ER_STAT_OK,
		ER_STAT_FAIL
	};
	mem::ER_MEM_INFO get_memory_info(__out mem_info **info);

	class mem_info {
	private:
		LPSTR						text_buffer;
		bool						verbose_info;

		PPROCESS_MEMORY_COUNTERS	mem_data;
	public:
		mem_info(bool verbosity) :
			verbose_info(verbosity),
			mem_data((PPROCESS_MEMORY_COUNTERS)mem::malloc(sizeof(PROCESS_MEMORY_COUNTERS))),
			text_buffer(NULL)
		{
			BOOL get_status = GetProcessMemoryInfo(GetCurrentProcess(), mem_data, sizeof(PROCESS_MEMORY_COUNTERS));
			if (!get_status) {
				mem::free(mem_data);
				mem_data = NULL;
				return;
			}

			// Print text
			
		}
		~mem_info(VOID)
		{
			if (mem_data == NULL) {
				printf("[+] Failure to obtain memory information!\n");
			}

			if (text_buffer != NULL) mem::free(text_buffer);

			mem::free(mem_data);
		}

		VOID mem_info::print(VOID) const
		{
			if (mem_data != NULL && (text_buffer == NULL)) {
				printf("[*] mem_info:\n\t-> Page Faults: \t%.02d/s\n", (int)mem_data->PageFaultCount, mem_data->PageFaultCount);
				printf("\t-> Working set size: \t%d\n", mem_data->WorkingSetSize);
				printf("\t-> Page File Usage: \t%d\n", mem_data->PagefileUsage);
			}
		}
	};

	// Buffer class ///////////////////////////////////////////////////////////
	class buffer;
	typedef std::shared_ptr<mem::buffer> Buffer;

	class buffer {
	private:
		typedef BYTE							ELEMENT, *PELEMENT;
		std::unique_ptr<std::vector<ELEMENT>>	element_array;
	public:
		buffer(VOID) :
			element_array(new std::vector<ELEMENT>)
			{

			}
		buffer(__in const LPVOID input, __in const UINT size) :
			element_array(new std::vector<ELEMENT>(size))
			{
				PELEMENT ptr = (PELEMENT)input;
				for (std::vector<ELEMENT>::iterator i = element_array->begin();
					i != element_array->end(); i++, ptr++) {

					i = element_array->erase(i);
					i = element_array->insert(i, *ptr);
				}
			}
		~buffer(VOID)
		{

		}

		// Array subscription
		BYTE &operator[](__in const UINT i)
		{
			return (*element_array)[i];
		}
	};

	class buffer2;
#define IS_NULL(x) x.get_is_null() == true

	class buffer2 {
	private:
		LPVOID					buffer;
		UINT					buffer_size;

		Ptr<std::vector<BYTE>>	Elements;

	public:
		buffer2(__in const LPVOID raw_buffer, __in const UINT raw_buffer_size) :
			buffer((LPVOID)mem::malloc(raw_buffer_size)),
			buffer_size(raw_buffer_size),
			Elements(new std::vector<BYTE>())
			{
				if (raw_buffer_size == 0) {
					return;
				}

				mem::copy(buffer, raw_buffer, buffer_size);

#ifndef DISABLE_BUFFER2_VECTORED
				PBYTE ptr = (PBYTE)raw_buffer;
				for (UINT c = 0; c < raw_buffer_size; c++) {
					Elements->push_back(ptr[c]);
				}
#endif
			}

		// Only allocate
		buffer2(__in const UINT size) :
			buffer((LPVOID)mem::malloc(size)),
			buffer_size(size),
			Elements(new std::vector<BYTE>())
			{

			}

		buffer2(__in const buffer2 *o) :
			buffer_size(o->buffer_size), buffer((LPVOID)mem::malloc(o->buffer_size)),
			Elements(new std::vector<BYTE>())
		{
			mem::copy(this->buffer, o->buffer, this->buffer_size);

#ifndef DISABLE_BUFFER2_VECTORED
			for (std::vector<BYTE>::iterator i = o->Elements->begin(); i != o->Elements->end(); i++) {
				Elements->push_back(*i);
			}
#endif
		}

		buffer2(__in buffer2& o) :
			buffer_size(o.buffer_size), buffer((LPVOID)mem::malloc(o.buffer_size)),
			Elements(new std::vector<BYTE>())
		{
			mem::copy(this->buffer, o.buffer, o.buffer_size);

#ifndef DISABLE_BUFFER2_VECTORED
			for (std::vector<BYTE>::iterator i = o->Elements->begin(); i != o->Elements->end(); i++) {
				Elements->push_back(*i);
			}
#endif
		}

#ifndef DISABLE_BUFFER2_COPY_CONSTRUCTOR
		buffer2(__in const buffer2& o) :
			buffer_size(o.buffer_size), buffer((LPVOID)mem::malloc(o.buffer_size)),
			Elements(new std::vector<BYTE>())
		{
			mem::copy(this->buffer, o.buffer, o.buffer_size);

#ifndef DISABLE_BUFFER2_VECTORED
			for (std::vector<BYTE>::iterator i = o->Elements->begin(); i != o->Elements->end(); i++) {
				Elements->push_back(*i);
			}
#endif
		}
#endif

		// Unknown size, just create the object
		buffer2(VOID) :
			buffer(NULL),
			buffer_size(0),
			Elements(new std::vector<BYTE>())
		{

		}

		buffer2(__in const LPSTR data, __in const UINT data_length) :
			buffer(mem::malloc(data_length + sizeof('\0'))),
			buffer_size(data_length),
			Elements(new std::vector<BYTE>())
		{							 
			mem::copy(buffer, data, buffer_size);		   
			for (UINT i = 0; i < buffer_size; i++) {
				Elements->push_back((BYTE)data[i]);
			}
		}

		~buffer2(VOID)
		{
			mem::free(buffer);
		}

		const LPVOID operator*(void) const
		{
			return this->buffer;
		}

		const bool operator==(__in const LPVOID o) const
		{
			DebugBreak();
			return true;
		}

		void operator++(void) 
		{
			this->buffer_size++;
			this->buffer = mem::realloc(this->buffer, this->buffer_size, true);
		}

		mem::buffer2 *operator+(__in const mem::buffer2& o)
		{
			this->buffer = mem::realloc(this->buffer, o.get_raw_size() + this->buffer_size, true);
			mem::copy((LPVOID)((DWORD_PTR)this->buffer + this->buffer_size, o.get_raw_buffer()), 
				o.get_raw_buffer(), o.get_raw_size());

			this->buffer_size += o.get_raw_size();

			return this;
		}

		void get_raw_data(__out LPVOID *data, __out PUINT data_size) const
		{
			if (data == NULL) {
				return;
			}

			*data = this->buffer;
			*data_size = this->buffer_size;
		}

		UINT get_raw_size(VOID) const
		{
			return this->buffer_size;
		}

		LPVOID get_raw_buffer(VOID) const
		{
			return this->buffer;
		}

		typedef DWORD BUFFER_POSITION;
		BYTE get_byte_position(__in const BUFFER_POSITION position)
		{
#ifdef DISABLE_BUFFER2_VECTORED
			if (Elements->size() == 0) {
				PBYTE ptr = (PBYTE)this->buffer;
				for (UINT c = 0; c < this->buffer_size; c++) {
					Elements->push_back(ptr[c]);
				}
			}
#endif

			return (*Elements)[position];
		}

		void set_byte_position(__in const BUFFER_POSITION position, __in const BYTE set)
		{
#ifdef DISABLE_BUFFER2_VECTORED
			if (Elements->size() == 0) {
				PBYTE ptr = (PBYTE)this->buffer;
				for (UINT c = 0; c < this->buffer_size; c++) {
					Elements->push_back(ptr[c]);
				}
			}
#endif

			Elements->at(position) = *(PBYTE)((DWORD_PTR)this->buffer + position) = set;
		}

		bool append(__in const LPVOID buffer_in, __in const UINT buffer_size_in)
		{
			LPVOID new_buffer = 
				(LPVOID)mem::realloc(this->buffer, this->buffer_size + buffer_size_in, true);
			mem::copy((LPVOID)((DWORD_PTR)new_buffer + this->buffer_size), buffer_in, buffer_size_in);
			mem::free(this->buffer);
			this->buffer = new_buffer;
			this->buffer_size += buffer_size_in;

#ifdef DISABLE_BUFFER2_VECTORED
			if (Elements->size() != 0) {
				PBYTE ptr = (PBYTE)buffer_in;
				for (UINT c = 0; c < buffer_size_in; c++) {
					Elements->push_back(*(PBYTE)&ptr[c]);
				}
			}
#else 
			PBYTE ptr = (PBYTE)buffer_in;
			for (UINT c = 0; c < buffer_size_in; c++) {
				Elements->push_back(*(PBYTE)&ptr[c]);
			}
#endif	  
			return true;
		}

		bool append(__in const mem::buffer2& buffer_in);

		// Used for string buffers
		void append_null(types::DEFAULT_NO_PARAMETERS)
		{
			LPVOID new_buffer = 
				(LPVOID)mem::realloc(this->buffer, this->buffer_size + sizeof(BYTE), true);
			this->buffer = new_buffer;
			this->buffer_size++;

#ifdef DISABLE_BUFFER2_VECTORED
			if (this->Elements->size() > 0) {
				this->Elements->push_back(0x00);
			}
#else 
			this->Elements->push_back(0x00);
#endif
		}
	};
};

typedef Ptr<mem::buffer2> Buffer2;

#ifdef USE_CUSTOM_ALLOCATOR
#undef new
void *operator new(__in const std::size_t length);
#endif