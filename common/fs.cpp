#include <Windows.h>

#include "fs.h"

#include "api.h"
#include "debug/error.h"
#include "common/mem.h"
#include "common/str.h"

class file_data {
private:

public:

};

mem::buffer2 *fs::read_raw_into_buffer_(__in const str_string& file_name)
{
	ERROR_CODE			status;

	HANDLE				handle						= INVALID_HANDLE_VALUE;
	DWORD				size_high, size_low;
	PDWORD				buffer;
	DOUBLE				size;
	INT					junk;

	handle = cCreateFileA(		*file_name, 
								GENERIC_READ, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	size_low		= cGetFileSize(handle, &size_high);
	size			= (size_low | size_high);

	buffer			= (DWORD *)mem::malloc(size_low);
	if (buffer == NULL) {
		cCloseHandle(handle);
		return NULL;
	}

	status			= cReadFile(handle, buffer, size_low, (LPUINT)&junk, NULL);
	if (!status) {
		cCloseHandle(handle);
		return NULL;
	}

	cCloseHandle(handle);
	mem::buffer2 *raw_buffer = new mem::buffer2((LPVOID)buffer, (UINT)size_low);

	return raw_buffer;
}

BOOL fs::read_raw_into_buffer(	__in	LPCSTR	file_name,
								__out	PUINT	file_size,
								__out	LPVOID	*out_file)
{
	ERROR_CODE			status;

	HANDLE				handle						= INVALID_HANDLE_VALUE;
	DWORD				size_high, size_low;
	PDWORD				buffer;
	DOUBLE				size;
	INT					junk;

	handle = cCreateFileA(		file_name, 
								GENERIC_READ, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	size_low		= cGetFileSize(handle, &size_high);
	if (size_low == 0) {
		//D("[+] FS: File %s contains %d bytes.\n", file_name, size_low);
		*file_size = 0;
		*out_file = NULL;
	}
	size			= (size_low | size_high);

	buffer			= (DWORD *)mem::malloc(size_low);
	if (buffer == NULL) {
		cCloseHandle(handle);
		return FALSE;
	}

	status			= cReadFile(handle, buffer, size_low, (LPUINT)&junk, NULL);
	if (!status) {
		cCloseHandle(handle);
		return FALSE;
	}

	cCloseHandle(handle);
	*file_size	= (UINT)size;
	*out_file	= buffer;

	return TRUE;
}

bool fs::write_raw_to_disk_(	__in str_string& file_name,
								__in mem::buffer2& raw_data)
{

	cDeleteFileA(*file_name);

	HANDLE file_handle = cCreateFileA(	*file_name,
										GENERIC_READ | GENERIC_WRITE,
										0,
										NULL,
										CREATE_ALWAYS,
										FILE_ATTRIBUTE_NORMAL,
										NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return false;
	}			   

	DWORD written = 0;
	BOOL write_status = cWriteFile(	file_handle,
									*raw_data,
									raw_data.get_raw_size(),
									(LPDWORD)&written,
									NULL);
	if (write_status == FALSE || written != raw_data.get_raw_size()) {
		return false;
	}

	cCloseHandle(file_handle);

	file_handle = INVALID_HANDLE_VALUE;

	return true;
}

BOOL fs::write_raw_to_disk(	LPCSTR	file_name,
							PDWORD	buffer,
							UINT	size)
{
	HANDLE	file_handle;
	INT		junk;

	file_handle = cCreateFileA(	(LPCSTR)file_name, 
							GENERIC_WRITE, 
							FILE_SHARE_READ, 
							NULL, 
							CREATE_ALWAYS, 
							FILE_ATTRIBUTE_NORMAL, 
							NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	cWriteFile(file_handle, buffer, size, (LPDWORD)&junk, NULL);
	cCloseHandle(file_handle);

	return TRUE;
}

BOOL fs::append_raw_to_disk(LPCSTR file_name, PDWORD buffer, UINT size)
{
	HANDLE file_handle;
	INT junk;

	file_handle = cCreateFileA(file_name,
								FILE_APPEND_DATA,
								FILE_SHARE_READ,
								NULL,
								OPEN_ALWAYS,
								FILE_ATTRIBUTE_NORMAL,
								NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	cWriteFile(file_handle, buffer, size, (LPDWORD)&junk, NULL);
	cCloseHandle(file_handle);

	return TRUE;
}