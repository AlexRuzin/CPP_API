#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "ID: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "ID: Loading standard memory module (32)")
#endif
#endif

#include "common/mem.h"
#include "crypt/crypt.h"
#include "api.h"

#pragma once

#define DISABLE_ID_TRACKING
#ifdef DISABLE_ID_TRACKING
#ifndef DISABLE_SECONDARY_OUTPUT
#pragma message (OUTPUT_PRIMARY "ID: Disabling ID Tracking")
#endif
#endif

#define NUMBER_OF_ELEMENTS		4

namespace id_info {
	class id;

#ifndef DISABLE_ID_TRACKING
	static std::vector<id *> *id_list		= new std::vector<id *>();
#endif

	static const UINT number_of_elements	= NUMBER_OF_ELEMENTS;

	// Sync
#ifndef DISABLE_ID_TRACKING
	static PCRITICAL_SECTION id_sync		= NULL;
#endif


	class id {
	private:
		// Random buffer 		
		Ptr<crypt::rand_buffer>					RandBuffer;

		Ptr<std::vector<BYTE>>					IdElements;

		Ptr<str_string>							RawString;

		DWORD									dword_value;

		bool									is_ok;
	public:
		id(VOID) :
			IdElements(new std::vector<BYTE>),
			RawString(NULL),
			RandBuffer(new crypt::rand_buffer(id_info::number_of_elements)),
			dword_value(0), is_ok(true)
		{
#ifndef DISABLE_ID_TRACKING
			if (id_sync == NULL) {
				id_sync = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
				cInitializeCriticalSection(id_sync);
			}
#endif

			// Generate key
			std::vector<BYTE> *current_array= RandBuffer->get_array();	
			for (std::vector<BYTE>::iterator i = current_array->begin();
				i != current_array->end(); i++) {

				IdElements->push_back(*i);
			}

			// Add self to id_list
#ifndef DISABLE_ID_TRACKING
			cEnterCriticalSection(id_sync);
			id_list->push_back(this);
			cLeaveCriticalSection(id_sync);
#endif

			// Generate DWORD id
			DWORD tmp = 0;
			UINT c = 0;
			for (std::vector<BYTE>::iterator i = this->IdElements->begin(); 
				i != IdElements->end(); i++, c++) 
			{
				tmp = *i | tmp;

				if (c == (sizeof(DWORD) - 1)) {
					break;
				}

				tmp = tmp << 8;
			}

			this->dword_value = tmp;
		}

		id(std::vector<BYTE>& input) :
			IdElements(new std::vector<BYTE>()),
			RawString(NULL), RandBuffer(NULL),
			dword_value(0), is_ok(true)
		{
			for (std::vector<BYTE>::iterator i = input.begin();
				i != input.end(); i++) {

				IdElements->push_back(*i);
			}

			// Generate DWORD id
			DWORD tmp = 0;
			UINT c = 0;
			for (std::vector<BYTE>::iterator i = this->IdElements->begin(); 
				i != IdElements->end(); i++, c++) 
			{
				tmp = *i | tmp;

				if (c == (sizeof(DWORD) - 1)) {
					break;
				}

				tmp = tmp << 8;
			}

			this->dword_value = tmp;

#ifndef DISABLE_ID_TRACKING
			cEnterCriticalSection(id_sync);
			id_list->push_back(this);
			cLeaveCriticalSection(id_sync);
#endif
		}

		id(__in const DWORD raw_id) :
			IdElements(new std::vector<BYTE>), RawString(NULL), RandBuffer(NULL),
			dword_value(raw_id), is_ok(true)
		{
			for (UINT i = 0; i < sizeof(DWORD); i++) {
				IdElements->push_back((BYTE)(((raw_id >> (8 * i)) & 0x000000ff)));
			}
		}

		// Take a string as input, create ID based on that
		id(__in const LPSTR input_string) :
			IdElements(NULL),
			RawString(NULL), RandBuffer(NULL),
			dword_value(0), is_ok(true)
		{
			this->IdElements = str::string_to_byte_vector(input_string);
			if (this->IdElements.get_value() == NULL) {
				this->is_ok = false;
			}
		}

		~id()
		{

		}

		
		crypt::rand_buffer *id::get_rand_buffer(VOID) 
		{
			return RandBuffer.get_value();
		}

		BYTE id::get_byte_at_offset(__in const types::OFFSET32 offset) const
		{
			return this->IdElements->at(offset);
		}

		str_string *id::get_string(VOID)
		{
			if (RawString == NULL) {
				RawString = str::byte_vector_to_string(*IdElements);
			}

			return RawString.get_value();
		}

		// Special function for only 4 bytes
		DWORD id::get_dword(void) const;

		// Operators
		/*
		bool id::operator==(__in id& other)
		{
			return (*RandData == *other.get_rand_buffer());
		}*/
	};
};