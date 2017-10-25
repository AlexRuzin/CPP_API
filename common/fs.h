#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "fs: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "fs: Compiling 32-bit.")
#endif
#endif

#include "common/mem.h"
#include "common/str.h"

namespace fs
{
	bool write_raw_to_disk_(	__in str_string& file_name,
								__in mem::buffer2& raw_data);

	// Returns mem::buffer2
	mem::buffer2 *read_raw_into_buffer_(__in const str_string& file_name);

	// Read file into buffer
	BOOL read_raw_into_buffer(	__in	LPCSTR	file_name,
								__out	PUINT	file_size,
								__out	LPVOID	*out_file);

	BOOL write_raw_to_disk(		LPCSTR	file_name,
								PDWORD	buffer,
								UINT	size);

	BOOL append_raw_to_disk(	LPCSTR file_name, 
								PDWORD buffer, 
								UINT size);

	class raw_file {

	private:
		LPVOID			raw_buffer;
		UINT			raw_buffer_size;

		Buffer2			RawBuffer;

		bool			is_loaded;

	public:
		raw_file::raw_file(__in const str_string& location) :
			raw_buffer(NULL), raw_buffer_size(0),
			RawBuffer(NULL), 
			is_loaded(false)
		{
			RawBuffer = fs::read_raw_into_buffer_(location);


			if (RawBuffer.get_is_null()) {
				return;
			}  

			raw_buffer		= **RawBuffer;
			raw_buffer_size = RawBuffer->get_raw_size();

			this->is_loaded = true;
		}

		~raw_file(VOID)
		{

		}

		UINT get_size(void) const
		{
			return this->raw_buffer_size;
		}

		// Operators
		const mem::buffer2& operator*(void) const
		{
			return *this->RawBuffer;
		}
	};
}
/*
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define BUFSIZE 1024
#define MD5LEN  16

DWORD main()
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	LPCWSTR filename=L"filename.txt";
	// Logic to check usage goes here.

	hFile = CreateFile(filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", filename, 
			dwStatus); 
		return dwStatus;
	}

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, 
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus); 
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		printf("MD5 hash of file %s is: ", filename);
		for (DWORD i = 0; i < cbHash; i++)
		{
			printf("%c%c", rgbDigits[rgbHash[i] >> 4],
				rgbDigits[rgbHash[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus); 
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return dwStatus; 
} */