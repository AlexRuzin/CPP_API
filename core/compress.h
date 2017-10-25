// Example
/*
#define ZIP_TEST "asdfffffffffffffffddsfssaffs"
	Buffer2 ZipBuffer = new mem::buffer2((const LPVOID)ZIP_TEST, str::lenA(ZIP_TEST));
	(*ZipBuffer)++;
	Ptr<compressor::zip_compress> ZipTest = new compressor::zip_compress(*ZipBuffer);
	ZipTest->process_data();

	const mem::buffer2 &compressed_data = ZipTest->get_processed_data();

	Ptr<compressor::zip_decompress> ZipDecomp = 
		new compressor::zip_decompress(compressed_data, ZipBuffer->get_raw_size());
	ZipDecomp->process_data();

	const mem::buffer2 &decompressed_data = ZipDecomp->get_processed_data();
*/

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
#pragma message (OUTPUT_PRIMARY "compress: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "compress: Compiling 32-bit.")
#endif
#endif

#include "common/mem.h"

#include "external/miniz.h"

// Default compression level (0-9)
#define DEFAULT_COMPRESSION_LEVEL			9

// Link to miniz.c 
#define miniz_MZ_OK MZ_OK

#define miniz_compress_bound compressBound
#define miniz_deflate_bound deflateBound
#define miniz_compress2 compress2
#define miniz_uncompress uncompress


namespace compressor {

	static const int default_compression_level = DEFAULT_COMPRESSION_LEVEL;

	typedef struct compress_encrypt_data {
		UINT				decompressed_size;
		DWORD				encryption_xor;
	} COMPRESS_ENCRYPT_DATA, *PCOMPRESS_ENCRYPT_DATA;


	class zip {
	protected:

		Buffer2		RawData;
		Buffer2		ProcessedData;

		bool		is_compressed, is_decompressed;

	public:	 
		// Performs either compression, or decompression
		virtual bool process_data(__inout PUINT size) = 0;

		// Return the processed data (either compressed or decompressed)
		const mem::buffer2& get_processed_data(void) const
		{
			return *ProcessedData;
		}
	};

	class zip_compress : public zip {

	public:
		zip_compress::zip_compress(__in const mem::buffer2& decompressed_buffer)
		{
			this->is_compressed		= false;
			this->is_decompressed	= false;
			this->RawData = new mem::buffer2(
				decompressed_buffer.get_raw_buffer(), decompressed_buffer.get_raw_size());
			this->ProcessedData = NULL;
		}

		// Compress the decompressed buffer
		virtual bool process_data(__inout PUINT size);		  
		
		mem::buffer2 *get_compressed_buffer(void) const
		{
			if (this->is_compressed == false) {
				return NULL;
			}

			return this->ProcessedData.get_value();
		}
	};

	class zip_decompress : public zip {
	private:
		mz_ulong decomp_len;

	public:
		zip_decompress::zip_decompress(
			__in const mem::buffer2& compressed_buffer) :
			decomp_len((mz_ulong)0)
		{
			this->RawData = new mem::buffer2(
				compressed_buffer.get_raw_buffer(), compressed_buffer.get_raw_size());
			this->ProcessedData = NULL;
		}

		// Decompresses already compressed data
		virtual bool process_data(__inout PUINT size);


		mem::buffer2 *get_decompressed_data(void) const
		{
			if (this->is_decompressed == false) {
				return NULL;
			}

			return this->ProcessedData.get_value();
		}
	};

}