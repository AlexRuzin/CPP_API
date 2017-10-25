#pragma once
#include <Windows.h>

#ifdef USE_PE
#error "USE_PE apready defined"
#endif
#define USE_PE

#ifndef USE_MEM
#include "common/mem.h"
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#include "crypt/crypt.h"

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "PE: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "PE: Compiling 32-bit.")
#endif
#endif

// Force disable zip compression on last segment packaging
#define DISABLE_COMPRESS_ON_PACKER

// The random pool used for the last segment encryption key
#define LAST_SEG_ENC_POOL		2048

// -1  is used as compressed the size (in last_seg_hdr) if no compression is used
#define LAST_SEG_NO_COMP		-1

// When adding a last section, this will be its total length (except the . at front)
#define LAST_SEG_NAME_LEN		3

// Magic signatures
#define DOS_MAGIC				'ZM'
#define PE_MAGIC				'EP'

// Signature for compression/encryption of last segment
#define LAST_SEG_ENC_SIG		'FU'

namespace pe {

	// Constants
	static const UINT last_seg_enc_pool = LAST_SEG_ENC_POOL; 
	static const INT last_seg_no_comp	= LAST_SEG_NO_COMP;
	static const UINT last_seg_name_len	= LAST_SEG_NAME_LEN;

	static const WORD dos_magic			= DOS_MAGIC;
	static const WORD pe_magic			= PE_MAGIC;

	static const WORD last_seg_enc_sig	= LAST_SEG_ENC_SIG;

	typedef DWORD PE_ERROR;
	enum {
		ER_PE_OK,
		ER_PE_GENERAL_FAILURE,
		ER_PE_ADD_SEGMENT
	};


	// Check if the PE is valid
	bool is_raw_valid(const LPVOID raw);

	// Header info
	typedef struct {

	} SEC_HDR, *PSEC_HDR;
	typedef PSEC_HDR PFIRST_SECTION;
	typedef struct {
		PIMAGE_DOS_HEADER		dos_header;
		PIMAGE_NT_HEADERS		nt_headers;
		PIMAGE_FILE_HEADER		file_header;
		PFIRST_SECTION			first_section;
		
	} HEADERS, *PHEADERS;

	// Returns the IMAGE_DOS_HEADER
	static const WORD mz_signature = 'ZM';
	PIMAGE_DOS_HEADER get_dos_header(LPVOID raw);

	// Returns the IMAGE_NT_HEADERS
	static const WORD pe_signature = 'EP';
	PIMAGE_NT_HEADERS get_nt_headers(LPVOID raw);

	// Returns the first section
	PFIRST_SECTION get_first_section(PIMAGE_NT_HEADERS nt_headers);

	// Raw/virtual PE geometry	
	typedef struct {
		LPVOID					raw;
		HEADERS					headers;
		UINT					number_of_sections;
		UINT					raw_size;
		UINT					virtual_size;
		DWORD					file_alignment;
		DWORD					virtual_alignment;
		DWORD					base_address;
		BOOL					is_dll_movable;
	} PE_GEOMETRY, *PPE_GEOMETRY;
	PPE_GEOMETRY get_file_geometry(const LPVOID raw);

	// Converts the running virtual image into a raw physical image
	LPVOID convert_virtual_to_raw(__in LPVOID virtual_image, __out PUINT raw_size);

	// Adds a last segment to a raw PE
#define round(n, r)						(((n+(r-1))/r)*r)
	PE_ERROR add_last_segment_to_raw(	__in	LPVOID target_binary,
										__in	UINT target_binary_size,
										__in	LPVOID last_section,
										__in	UINT last_section_size,
										__out	LPVOID *out,
										__out	PUINT out_size);

	// Returns the last section of the PE (raw)
	PIMAGE_SECTION_HEADER get_last_section(PPE_GEOMETRY geometry);

	// Returns the last section of a virtual loaded PE. Unpacking, spreading, etc
	bool return_last_virtual_section(__in LPVOID virtual_base, __out LPVOID *last_section, __out PUINT last_section_raw_size);

	// PE Object
	class raw_pe;
	typedef Ptr<raw_pe> RawPe;
	typedef struct last_seg_hdr {
		BYTE		is_encrypted;
		BYTE		is_compressed;
		WORD		signature;

		BYTE		key[crypt::md5_length];

		INT			decompressed_size;
			
		UINT		header_size;
		UINT		data_size;
		UINT		encrypted_data_size;

		last_seg_hdr(void)
		{
			is_encrypted			= FALSE;
			is_compressed			= FALSE;
			signature				= last_seg_enc_sig;
			data_size				= 0;	// Compressed size
			header_size				= sizeof(last_seg_hdr);
			decompressed_size		= 0;
			encrypted_data_size		= 0;
			mem::zeromem(key, sizeof(key));
		}
	} LAST_SEG_HDR, *PLAST_SEG_HDR;

	class raw_pe {

	private:
		Ptr<mem::buffer2>		RawBuffer;
		PPE_GEOMETRY			pe_geometry;

		bool					is_ok;

	public:
		raw_pe(__in const LPVOID raw_image, __in const UINT raw_image_size) :
			RawBuffer(new mem::buffer2(raw_image, raw_image_size)),
			is_ok(false),
			pe_geometry(NULL)
		{
			bool sanity_status = pe::is_raw_valid(RawBuffer->get_raw_buffer());
			if (sanity_status == false) {
				return;
			}

			pe_geometry = pe::get_file_geometry(RawBuffer->get_raw_buffer());
			if (pe_geometry == NULL) {
				return;				
			}
			
			this->is_ok = true;
		}

		raw_pe(__in const mem::buffer2 *raw_image) :
			RawBuffer(new mem::buffer2(raw_image->get_raw_buffer(), raw_image->get_raw_size())),
			is_ok(false),
			pe_geometry(NULL)
		{
			bool sanity_status = pe::is_raw_valid(RawBuffer->get_raw_buffer());
			if (sanity_status == false) {
				return;
			}

			pe_geometry = pe::get_file_geometry(RawBuffer->get_raw_buffer());
			if (pe_geometry == NULL) {
				return;				
			}
			
			this->is_ok = true;
		}			

		raw_pe(__in const mem::buffer2& raw_image) :
			RawBuffer(new mem::buffer2(*raw_image, raw_image.get_raw_size())),
			is_ok(false),
			pe_geometry(NULL)
		{
			bool sanity_status = pe::is_raw_valid(RawBuffer->get_raw_buffer());
			if (sanity_status == false) {
				return;
			}

			pe_geometry = pe::get_file_geometry(RawBuffer->get_raw_buffer());
			if (pe_geometry == NULL) {
				return;				
			}
			
			this->is_ok = true;
		}

		~raw_pe(VOID)
		{
			if (pe_geometry != NULL) {
				mem::free(pe_geometry);
			}
		}
		
		// Does not realloc
		PPE_GEOMETRY get_geometry(VOID) const
		{
			return this->pe_geometry;
		}

		bool get_is_ok(VOID) const
		{
			return this->is_ok;
		}

		mem::buffer2 *get_raw_buffer(void) const
		{
			return this->RawBuffer.get_value();
		}

		bool adjust_nt_header_from_geometry(__inout PIMAGE_NT_HEADERS header, 
			__in const PPE_GEOMETRY geometry);


		// Modify header for new append segment
		bool append_last_segment(__in const mem::buffer2& raw_image,
			__in PPE_GEOMETRY geo);

		// Header for last segment data
	private:

		/*
		typedef struct last_seg_hdr {
			BYTE		is_encrypted;
			BYTE		is_compressed;
			BYTE		signature;

			BYTE		key[crypt::md5_length];

			INT			decompressed_size;
			
			UINT		header_size;
			UINT		data_size;

			last_seg_hdr(void)
			{
				is_encrypted	= FALSE;
				is_compressed	= FALSE;
				signature		= last_seg_enc_sig;
				mem::zeromem(key, sizeof(key));
				data_size = 0;	// Compressed size
				header_size = sizeof(last_seg_hdr);
				decompressed_size = 0;
			}
		} LAST_SEG_HDR, *PLAST_SEG_HDR;
		*/

		// Adds another PE binary as a last segment
	public:
		bool add_pe_as_last_segment(__in const pe::raw_pe& bin, 
									__in const bool encrypt,
									__in const bool compress);

		// Adds data as a last segment
		bool add_data_as_last_segment(__in const mem::buffer2& bin, 
									  __in const bool encrypt,
									  __in const bool compress)
		{
			//todo
			return false;
		}
	};
}