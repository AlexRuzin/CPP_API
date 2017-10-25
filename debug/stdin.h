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
#pragma message (OUTPUT_PRIMARY "stdin: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "stdin: Compiling 32-bit.")
#endif
#endif

#include <Windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#pragma once

#include "common/str.h"
#include "common/mem.h"

//#include "debug/console.h"

#ifdef DEBUG_OUT
//using namespace console;
#endif

#define STANDARD_PROMPT "(user)> "

namespace text_io {
	static str_string *standard_prompt = new str_string(STANDARD_PROMPT);

	class input {
	private:
		str_string			*raw_input;
		LPSTR				hard_input;

		StrString			RawOutput;

		bool				is_anything;
	public:
		input(VOID) : // take random input from stdin
			raw_input(NULL),
			hard_input(NULL),
			RawOutput(NULL),
			is_anything(false)
		{
			std::string input;
			//setcolor(green,black);
			std::cout << standard_prompt->to_lpstr();
			//setcolor(white,black);
			std::getline(std::cin, input);
			LPSTR tmp = (LPSTR)input.data();
			UINT tmp_size = str::lenA(tmp);
			if (tmp_size == 0) {
				return;
			}
			this->hard_input = (LPSTR)mem::malloc(tmp_size + str::ASCII_CHAR);
			mem::copy(this->hard_input, tmp, tmp_size);

			this->RawOutput = new str_string(this->hard_input);

			this->is_anything = true;
		}

		input(__in str_string& prompt) :
			raw_input(NULL),
			hard_input(NULL),
			RawOutput(NULL),
			is_anything(false)
		{
			std::string input;
			//setcolor(green,black);
			std::cout << prompt.to_lpstr();
			//setcolor(white,black);
			std::getline(std::cin, input);
			LPSTR tmp = (LPSTR)input.data();
			UINT tmp_size = str::lenA(tmp);
			if (tmp_size == 0) {
				return;
			}
			this->hard_input = (LPSTR)mem::malloc(tmp_size + str::ASCII_CHAR);
			mem::copy(this->hard_input, tmp, tmp_size);

			this->RawOutput = new str_string(this->hard_input);

			this->is_anything = true;
		}

		input(__in const LPSTR prompt):
			raw_input(NULL),
			hard_input(NULL),
			RawOutput(NULL),
			is_anything(false)
		{
			std::string input;
			//setcolor(green,black);
			std::cout << prompt;
			//setcolor(white,black);
			std::getline(std::cin, input);
			LPSTR tmp = (LPSTR)input.data();
			UINT tmp_size = str::lenA(tmp);
			if (tmp_size == 0) {
				return;
			}
			this->hard_input = (LPSTR)mem::malloc(tmp_size + str::ASCII_CHAR);
			mem::copy(this->hard_input, tmp, tmp_size);

			this->RawOutput = new str_string(this->hard_input);

			this->is_anything = true;
		}

		~input(VOID)
		{
			if (raw_input != NULL) delete raw_input;
			if (hard_input != NULL) mem::free(hard_input);
		}

		LPSTR get_raw_input(VOID) const
		{
			return this->hard_input;
		}

		UINT get_raw_size(VOID) const
		{
			return str::lenA(this->hard_input);
		}

		str_string *get_string(VOID) const
		{
			return RawOutput.get_value();
		}

		bool get_is_anything(VOID) const
		{
			return this->is_anything;
		}
	};
}