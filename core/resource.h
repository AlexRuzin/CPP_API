#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>

#include "api.h"
#include "common/mem.h"
#include "common/str.h"

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "Resource: Loading standard module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "Resource: Loading standard module (32)")
#endif

namespace resource {

	class instance {
	private:
		Ptr<str_string>		Name;
		WORD				id;

		HMODULE				current_module;

		Ptr<mem::buffer2>	RawData;

		typedef struct handles {
			HRSRC				resource_handle;
			HGLOBAL				global_handle;
			
			handles(VOID) 
			{
				resource_handle	= NULL;
				global_handle	= NULL;
			}
		} HANDLES, *PHANDLES;
		Ptr<HANDLES>		Handles;

	public:
		instance(__in const LPSTR name, __in const WORD id);

		~instance(types::DEFAULT_NO_PARAMETERS)
		{
			if (this->Handles->global_handle != NULL) {
				
			}
		}

		mem::buffer2 *get_buffer_(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->RawData.get_value();
		}

		UINT get_size(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->RawData->get_raw_size();
		}

		LPVOID get_buffer(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->RawData->get_raw_buffer();
		}

		bool get_is_ok(types::DEFAULT_NO_PARAMETERS) const
		{
			if (this->Handles->global_handle != NULL) {
				return true;
			}

			return false;
		}

		// Adds a NULL byte to the end of the resource (used for string parsing)
		void add_null(types::DEFAULT_NO_PARAMETERS);
	};
};