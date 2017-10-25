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
#pragma message (OUTPUT_PRIMARY "args: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "args: Compiling 32-bit.")
#endif
#endif

#include "common/str.h"

// Sanitize input
#define MAX_ARGUMENT_LENGTH		128
#define MAX_AMOUNT_OF_ARGS		32
#define MAX_AMOUNT_OF_ELE		MAX_AMOUNT_OF_ARGS / 2
#define MAX_AMOUNT_PER_ELEM		MAX_PATH					// Just set it to the max filename path

// Permanent constants
#define ARG_DASH				'-'
#define ARG_SWITCH_MAX_SIZE		1							// so a switch can only be like -m, not -mm


namespace args
{
	static const UINT max_agrument_length	= MAX_ARGUMENT_LENGTH;
	static const UINT max_amount_of_args	= MAX_AMOUNT_OF_ARGS;
	static const UINT max_amount_of_ele		= MAX_AMOUNT_OF_ELE;
	static const UINT max_amount_per_elem	= MAX_AMOUNT_PER_ELEM;

	static const CHAR arg_dash				= ARG_DASH;
	static const INT arg_switch_max_size	= ARG_SWITCH_MAX_SIZE;


	enum switch_style {
		 SWITCH_STYLE_SWITCHES,
		 SWITCH_STYLE_NO_SWITCHES
	};

	class argument_array;


	class argument_array {
	private:
		typedef struct element {
			CHAR 					switch_data;
			LPSTR					data;

			element(void) 
			{
				switch_data			= 0;
				data				= NULL;
			}
		} ELEMENT, *PELEMENT;	

		bool is_ok;

		UINT number_of_arguments;

		StrString					RunningProgramLocation;

		Ptr<std::vector<PELEMENT>>	ElementArray;
		
		// Do we use switches like -m/-q or just names like blablablafilename
		bool switch_style;

	public:
		// Style is the switch_style enum
		argument_array(int c, char* v[], enum switch_style style);


		bool get_is_ok(void) const
		{
			return this->is_ok;
		}

		UINT get_total_args(VOID) const
		{
			return this->number_of_arguments;
		}

		UINT get_total_elements(VOID) const
		{
			return this->ElementArray->size();
		}

		const str_string& get_running_location(void) const
		{
			return *RunningProgramLocation;
		}

		const LPSTR get_value_for_switch(__in const CHAR switch_value);

	private:
		void clear_elements(__inout std::vector<PELEMENT> elements);
	};



}