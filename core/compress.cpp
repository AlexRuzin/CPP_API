#include <Windows.h>

#include "compress.h"
#include "external/miniz.h"
#include "common/mem.h"

using namespace compressor;

bool zip_compress::process_data(__inout PUINT size)
{
	unsigned char *decompressed_buffer = (unsigned char *)**this->RawData;	   
	mz_ulong compressed_size = miniz_compress_bound(this->RawData->get_raw_size());
	if (compressed_size == 0) return false;

	unsigned char *compressed_buffer = (unsigned char *)mem::malloc(compressed_size);
	int zip_status = miniz_compress2(compressed_buffer, 
		&compressed_size, 
		decompressed_buffer, 
		this->RawData->get_raw_size(), 
		compressor::default_compression_level);
	if (zip_status != miniz_MZ_OK) {
		mem::free(compressed_buffer);
		return false;
	}

	*size = compressed_size;
	this->ProcessedData	= new mem::buffer2(compressed_buffer, compressed_size);
	this->is_compressed = true;

	return true;
}

bool zip_decompress::process_data(__inout PUINT size)
{
	this->decomp_len = (mz_ulong)size;

	unsigned char *compressed_buffer = (unsigned char *)**this->RawData;
	unsigned char *decompressed_buffer	= (unsigned char *)mem::malloc(this->decomp_len);

	int cmp_status = miniz_uncompress(decompressed_buffer, &this->decomp_len, 
		compressed_buffer, (mz_ulong)size);
	if (cmp_status != miniz_MZ_OK) {
		mem::free(decompressed_buffer);
		return false;
	}

	this->ProcessedData = new mem::buffer2(decompressed_buffer, this->decomp_len);
	this->is_decompressed = true;

	return true;
}

