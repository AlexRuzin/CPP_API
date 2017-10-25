#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#ifndef DISABLE_LIBRARY_INFO
#pragma message (OUTPUT_PRIMARY "PE Library: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "PE Library: Compiling 32-bit.")
#endif
#endif

#include "pe.h"

#include "common/mem.h"
#include "common/str.h"
#include "core/compress.h"

#ifndef DISABLE_COMPRESS_ON_PACKER
#include "core/compress.h"
#endif

using namespace pe;

bool pe::is_raw_valid(const LPVOID raw)
{
	PPE_GEOMETRY geometry = get_file_geometry(raw);
	if (geometry == NULL) return false;

	mem::free(geometry);

	return true;
}

pe::PPE_GEOMETRY pe::get_file_geometry(const LPVOID raw)
{
	PPE_GEOMETRY geometry = (PPE_GEOMETRY)mem::malloc(sizeof(PE_GEOMETRY));

	geometry->headers.dos_header = get_dos_header(raw);
	if (geometry->headers.dos_header == NULL) {
		mem::free(geometry);
		return NULL;
	}

	geometry->headers.nt_headers = get_nt_headers(raw);
	if (geometry->headers.nt_headers == NULL) {
		mem::free(geometry);
		return NULL;
	}

	geometry->headers.first_section		= get_first_section(geometry->headers.nt_headers);

	// Raw file size
	geometry->number_of_sections		= geometry->headers.nt_headers->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER current_section = (PIMAGE_SECTION_HEADER)geometry->headers.first_section;
	for (UINT i = 1; i < geometry->number_of_sections; i++) {
		current_section++;
	}
	geometry->raw_size					= (UINT)(current_section->PointerToRawData + current_section->SizeOfRawData);

	geometry->raw						= raw;
	geometry->virtual_size				= geometry->headers.nt_headers->OptionalHeader.SizeOfImage;
	geometry->file_alignment			= geometry->headers.nt_headers->OptionalHeader.FileAlignment;
	geometry->virtual_alignment			= geometry->headers.nt_headers->OptionalHeader.SectionAlignment;

	geometry->base_address				= geometry->headers.nt_headers->OptionalHeader.ImageBase;
	//geometry->is_dll_movable			= 

	return geometry;
}

pe::PFIRST_SECTION pe::get_first_section(PIMAGE_NT_HEADERS nt_headers)
{
	return (PFIRST_SECTION)IMAGE_FIRST_SECTION(nt_headers);
}

PIMAGE_DOS_HEADER pe::get_dos_header(LPVOID raw)
{
	if (raw == NULL) return NULL;

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)raw;
	if (dos_header->e_magic != pe::mz_signature) return NULL;

	return dos_header;
}

PIMAGE_NT_HEADERS pe::get_nt_headers(LPVOID raw)
{
	PIMAGE_DOS_HEADER dos_header = get_dos_header(raw);
	if (dos_header == NULL) return NULL;

	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)raw + dos_header->e_lfanew);
	if (nt_headers->Signature != pe::pe_signature) return NULL;

	return nt_headers;
}

LPVOID pe::convert_virtual_to_raw(__in LPVOID virtual_image, __out PUINT raw_size)
{
	// Check integrity, get geometry
	if (is_raw_valid(virtual_image) == false) return NULL;
	pe::PPE_GEOMETRY geometry = get_file_geometry(virtual_image);
	if (geometry == NULL) return NULL;

	// Allocate & copy segments
	LPVOID raw_image = (LPVOID)mem::malloc(geometry->raw_size);
	mem::copy(raw_image, virtual_image, geometry->headers.nt_headers->OptionalHeader.SizeOfHeaders); // Headers
	PIMAGE_SECTION_HEADER current_section = (PIMAGE_SECTION_HEADER)geometry->headers.first_section;
	for (UINT i = 0; i < geometry->number_of_sections; i++) {
		if (current_section->SizeOfRawData == 0) {
			current_section++;
			continue;
		}
		mem::copy(&((PBYTE)raw_image)[current_section->PointerToRawData], 
			&((PBYTE)virtual_image)[current_section->VirtualAddress],
			current_section->SizeOfRawData);
		current_section++;
	}

	*raw_size = geometry->raw_size;

	return raw_image;
}

PIMAGE_SECTION_HEADER pe::get_last_section(pe::PPE_GEOMETRY geometry)
{
	if (geometry == NULL) return NULL;

	PIMAGE_SECTION_HEADER current_section = (PIMAGE_SECTION_HEADER)geometry->headers.first_section;
	for (UINT i = 1; i < geometry->number_of_sections; i++) {
		current_section++;
	}

	return current_section;
}

pe::PE_ERROR pe::add_last_segment_to_raw(	__in	LPVOID target_binary,
											__in	UINT target_binary_size,
											__in	LPVOID last_section,
											__in	UINT last_section_size,
											__out	LPVOID *out,
											__out	PUINT out_size)
{
	if (target_binary == NULL || target_binary_size == 0 || last_section == NULL || last_section_size == 0) return ER_PE_ADD_SEGMENT;

	// Check integrity, return geometry
	if (is_raw_valid(target_binary) == false) return ER_PE_ADD_SEGMENT;
	PPE_GEOMETRY geometry = get_file_geometry(target_binary);
	if (geometry == NULL) return ER_PE_ADD_SEGMENT;

	// Build new buffer
	LPVOID new_buffer = (LPVOID)mem::malloc(target_binary_size + round(last_section_size, geometry->file_alignment));
	mem::copy(new_buffer, last_section, last_section_size);
	PIMAGE_SECTION_HEADER last_section_header = get_last_section(geometry);
	mem::copy((LPVOID)(&((PBYTE)new_buffer)[last_section_header->PointerToRawData + last_section_header->SizeOfRawData]),
			last_section, last_section_size);

	// Build IMAGE_SECTION_HEADER
	PPE_GEOMETRY new_geometry			= get_file_geometry(new_buffer);
	if (new_geometry == NULL) {
		mem::free(new_buffer);
		mem::free(geometry);
		return ER_PE_ADD_SEGMENT;
	}
	PIMAGE_SECTION_HEADER appended_section = get_last_section(new_geometry);
	appended_section++;
	mem::copy(appended_section->Name, ".dat", str::lenA(".dat"));
	appended_section->Misc.VirtualSize	= round(last_section_size, geometry->virtual_alignment);
	appended_section->SizeOfRawData		= round(last_section_size, geometry->file_alignment);
	appended_section->VirtualAddress	= (DWORD)(round(last_section_header->VirtualAddress + last_section_header->Misc.VirtualSize, geometry->virtual_alignment));
	appended_section->PointerToRawData	= (DWORD)(last_section_header->PointerToRawData + last_section_header->SizeOfRawData);
	appended_section->Characteristics	= 0x40000040;

	// Fix IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS nt_headers			= get_nt_headers(new_buffer);
	nt_headers->OptionalHeader.SizeOfImage	= (DWORD)(appended_section->VirtualAddress + appended_section->Misc.VirtualSize);
	nt_headers->FileHeader.NumberOfSections++;

	*out_size = target_binary_size + round(last_section_size, geometry->file_alignment);
	*out = new_buffer;

	mem::free(geometry);
	mem::free(new_geometry);
	return ER_PE_OK;
}

bool pe::return_last_virtual_section(__in LPVOID virtual_base, __out LPVOID *last_section, __out PUINT last_section_raw_size)
{
	if (virtual_base == NULL || is_raw_valid(virtual_base) == false) {
		return false;
	}

	PPE_GEOMETRY geometry = get_file_geometry(virtual_base);
	if (geometry == NULL) {
		return false;
	}

	PIMAGE_SECTION_HEADER last_section_header = get_last_section(geometry);
	if (last_section == NULL) {
		return false;
	}

	*last_section			= (LPVOID)((DWORD_PTR)virtual_base + last_section_header->VirtualAddress);
	*last_section_raw_size	= last_section_header->SizeOfRawData;

	mem::free(geometry);
	return true;
}

bool raw_pe::add_pe_as_last_segment(__in const pe::raw_pe& bin, 
									__in const bool encrypt, 
									__in const bool compress)
{
	if (bin.get_is_ok() == false) {
		return false;
	}

	if (encrypt == false || compress == false) {
		return false;
	}

	// Compress binary ///////////////////////////////////////////////////////////////////////////////////////
	Buffer2 RawLastSegment = new mem::buffer2(bin.get_raw_buffer());
	Ptr<compressor::zip_compress> CompressedLastSegment = new compressor::zip_compress(*RawLastSegment);
	INT compressed_size = 0; // Size of the compressed package
	bool compress_status = CompressedLastSegment->process_data((PUINT)&compressed_size);
	if (compress_status == false) {
		return false;
	}				  

	const mem::buffer2& compressed_data = CompressedLastSegment->get_compressed_buffer();

#ifdef DEBUG_OUT
	DBGOUT("[+] PE: Decompressed size: %d (0x%08x)\n[+] PE: Compressed size: %d (0x%08x)\n",
		bin.get_raw_buffer()->get_raw_size(),
		bin.get_raw_buffer()->get_raw_size(),
		compressed_data.get_raw_size(),
		compressed_data.get_raw_size());
#endif

	// Generate random pool
	LPVOID pool = NULL;
	crypt::GEN_ERROR gen_error = crypt::generate_random_buffer(&pool, pe::last_seg_enc_pool);
	if (gen_error == crypt::ER_FAIL) {
		return false;
	}

	// Generate key based on pool
	Buffer2 RandomPool		= new mem::buffer2(pool, pe::last_seg_enc_pool);
	mem::free(pool);
	pool = NULL;
	Ptr<crypt::md5> Key		= new crypt::md5(*RandomPool);

	// Encrypt binary ///////////////////////////////////////////////////////////////////////////////////////
	Ptr<crypt::encryption_buffer> EncryptionBuffer = new crypt::encryption_buffer(*Key, compressed_data, false);
	bool encryption_status = EncryptionBuffer->encrypt();
	if (encryption_status == false) {
		return false;
	}

	mem::buffer2 *encrypted_compressed_data = EncryptionBuffer->get_encrypted_data();
	if (encrypted_compressed_data == NULL) {
		return false;
	}	

	// Create header
	PLAST_SEG_HDR header		= new last_seg_hdr();
	header->encrypted_data_size	= encrypted_compressed_data->get_raw_size();
	header->is_encrypted		= TRUE;
	header->is_compressed		= TRUE;
	header->decompressed_size	= bin.get_geometry()->raw_size;
	std::vector<crypt::MD5_ELEMENT> *md5_array = Key->get_array();
	if (md5_array->size() != crypt::md5_length) {
		return false;
	}

	PBYTE ptr = (PBYTE)header->key;
	for (std::vector<crypt::MD5_ELEMENT>::const_iterator i = md5_array->begin();
		i != md5_array->end();
		i++, ptr++)
	{
		*ptr = *i;
	}

	//Key.clear();

	header->header_size			= sizeof(LAST_SEG_HDR);
	header->data_size			= encrypted_compressed_data->get_raw_size();	 

	// Generate buffer containing the last segment
	Buffer2 CompleteBuffer		= new mem::buffer2(round(sizeof(LAST_SEG_HDR) + 
		encrypted_compressed_data->get_raw_size(), this->get_geometry()->file_alignment));

	// Copy data to last segment
	mem::copy(**CompleteBuffer, header, sizeof(LAST_SEG_HDR));
	mem::copy((LPVOID)((DWORD_PTR)**CompleteBuffer + sizeof(LAST_SEG_HDR)),
		**encrypted_compressed_data, encrypted_compressed_data->get_raw_size());
	
	// Append to final image
	bool add_last_seg_status = append_last_segment(*CompleteBuffer, this->get_geometry());
	if (add_last_seg_status == false) {
		return false;
	}

	return true;
}

bool raw_pe::append_last_segment(__in const mem::buffer2& raw_image, __in PPE_GEOMETRY geo)
{
	if (geo == NULL) {
		return false;							 
	}	  

	// Create new segment header
	mem::buffer2 *raw_file			= this->get_raw_buffer();
	PBYTE ptr 						= (PBYTE)raw_file->get_raw_buffer();

	PIMAGE_DOS_HEADER dos_hdr		= (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt_hdr		= (PIMAGE_NT_HEADERS)((DWORD_PTR)ptr + dos_hdr->e_lfanew);

	PIMAGE_SECTION_HEADER last_seg	= get_last_section(geo);
	PIMAGE_SECTION_HEADER new_seg	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)last_seg + sizeof(IMAGE_SECTION_HEADER));
	
	// Name specifics
	LPBYTE name_buffer_bytes = NULL;
	crypt::GEN_ERROR gen_status		= crypt::generate_random_buffer((LPVOID *)&name_buffer_bytes, 2);

	// Generated 2 hexadecimal bytes, convert this to ascii
	LPBYTE name_buffer				= (LPBYTE)mem::malloc(IMAGE_SIZEOF_SHORT_NAME);

	// Generate name field
	name_buffer[0]					= '.';
	WORD tmp_letter					= str::convert_byte_to_ascii_word(name_buffer_bytes[0]);
	mem::copy(&name_buffer[1], &tmp_letter, sizeof(WORD));
	tmp_letter						= str::convert_byte_to_ascii_word(name_buffer_bytes[1]);
	mem::copy(&name_buffer[1 + sizeof(WORD)], &tmp_letter, sizeof(WORD));
	mem::copy(new_seg->Name, name_buffer, str::lenA((LPCSTR)name_buffer));
	mem::free(name_buffer);
#ifdef DEBUG_OUT
	DBGOUT("[+] PE: Segment name: %s\n", new_seg->Name);
#endif

	// Generate other elements of the last segment
	new_seg->Misc.VirtualSize		= round(raw_image.get_raw_size(), geo->virtual_alignment);
	new_seg->VirtualAddress			= round(last_seg->VirtualAddress + last_seg->Misc.VirtualSize, geo->virtual_alignment);
	new_seg->SizeOfRawData			= round(raw_image.get_raw_size(), geo->file_alignment);
	new_seg->Characteristics		= 0xC0000040;
	new_seg->PointerToRawData		= round(last_seg->PointerToRawData + last_seg->SizeOfRawData, 
										nt_hdr->OptionalHeader.FileAlignment);

#ifdef DEBUG_OUT
	DBGOUT("[+] PE: New Virtual Address: \t0x%08x\n", new_seg->VirtualAddress);
	DBGOUT("[+] PE: New SizeOfRawData: \t0x%08x\n", new_seg->SizeOfRawData);
	DBGOUT("[+] PE: New PointerToRawData: \t0x%08x\n", new_seg->PointerToRawData);
	DBGOUT("[+] PE: New VirtualSize: \t0x%08x\n", new_seg->Misc.VirtualSize);
#endif	 

	// Adjust NT headers
	geo->number_of_sections = ++nt_hdr->FileHeader.NumberOfSections;
	geo->virtual_size		= round(new_seg->VirtualAddress + new_seg->Misc.VirtualSize, geo->virtual_alignment);
	geo->raw_size			+= round(raw_image.get_raw_size(), nt_hdr->OptionalHeader.FileAlignment);

	bool header_status = adjust_nt_header_from_geometry(nt_hdr, geo);
	if (header_status == false) {
		return false;
	}

	bool append_status = this->RawBuffer->append(raw_image);	
	if (append_status == false) {
		return false;
	}

	return true;
}

bool pe::raw_pe::adjust_nt_header_from_geometry(__inout PIMAGE_NT_HEADERS header,
												__in const PPE_GEOMETRY geometry)
{
	header->OptionalHeader.SizeOfImage	= geometry->virtual_size;
	header->FileHeader.NumberOfSections	= geometry->number_of_sections;
	//header->OptionalHeader.si

	return true;
}