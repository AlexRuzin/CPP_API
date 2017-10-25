#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif
#include <vector>

#include "str.h"

#include "mem.h"
#include "core/core.h"
#include "debug/assert.h"
#include "debug/debug.h"

typedef DWORD OFFSET32;

// Ctors & Dtors
str_string::str_string(LPSTR target_stringA)
{
	//str_string();
	zero_init();

	this->lpstr_len = str::lenA(target_stringA);
	this->lpstr = NULL;
	this->lpwstr = NULL;

	this->is_unicode = false;

	if (target_stringA != NULL) {
		this->lpstr = (LPSTR)mem::malloc(str::lenA(target_stringA) + str::ASCII_CHAR);
		mem::copy(this->lpstr, target_stringA, str::lenA(target_stringA));
		this->is_ascii = true;
	}
};

str_string::str_string(LPWSTR target_stringW)
{
	//str_string();
	zero_init();
	
	this->lpstr = NULL;
	this->lpwstr = NULL;

	this->is_ascii = false;

	if (target_stringW != NULL) {
		this->lpwstr = (LPWSTR)mem::malloc(str::lenW(target_stringW) + str::UNICODE_CHAR);
		mem::copy(this->lpwstr, target_stringW, str::lenW(target_stringW));
		this->is_unicode = true;
	}
};

str_string::~str_string(VOID)
{
	if (this->lpstr != NULL) { 
		mem::free(this->lpstr);
		this->lpstr = NULL;
	}
	if (this->lpwstr != NULL) {
		mem::free(this->lpwstr);
		this->lpwstr = NULL;
	}

	if (temporary_line != NULL) mem::free(temporary_line);
	if (temporary_linew != NULL) mem::free(temporary_linew);
	if (raw_buffer != NULL) mem::free(raw_buffer);

	if (line_terminator.terminator != NULL) mem::free(line_terminator.terminator);

	if (raw_type_buffers.ascii != NULL) mem::free(raw_type_buffers.ascii);
	if (raw_type_buffers.unicode != NULL) mem::free(raw_type_buffers.unicode);
		
	if (first_line != NULL) {
		PLINE current_line = first_line;
		while (current_line != NULL) {
			PLINE tmp_line = current_line;
			current_line = current_line->next_line;
			mem::free(tmp_line);
		}
	}
		
	if (first_lineW != NULL) {
		PLINEW current_line = first_lineW;
		while (current_line != NULL) {
			PLINEW tmp_line = current_line;
			current_line = current_line->next_line;
			mem::free(tmp_line);
		}
	}

	if (vectored_lines != 0) delete vectored_lines;
}

// New Ctor for building PLINEs
str_string::str_string(STR_MODE mode, LPCSTR buffer, UINT buffer_size)
{
	//str_string();
	zero_init();

	//seq_const_state = true;

	if (mode == MODE_SPLIT_LINE) {
		this->is_unicode = false;
		init_string(buffer, NULL, buffer_size, 0, true);
		load_into_lines(str::carriage_return);
		remove_sequence_from_lines(str::carriage_return, str::lenA(str::carriage_return));	
	}
}

VOID str_string::zero_init(VOID)
{

	this->lpstr_len = 0;
	this->temporary_line = NULL;
	this->temporary_linew = NULL;
	this->raw_size = 0;
	this->raw_buffer = NULL;
	this->convert = false;
	this->first_line = NULL;
	this->first_lineW = NULL;
	this->current_line = NULL;
	this->current_lineW = NULL;
	this->get_line_buffers_line = NULL;
	this->current_line = NULL;
	this->get_line_buffers_lineW = NULL;
	this->vectored_lines = NULL;
	
	mem::zeromem(&this->raw_type_buffers, sizeof(type_buffers));
	mem::zeromem(&this->line_terminator, sizeof(term_store));

	return;
}



// New methods ////////////////////////////////////////////////////////////////
UINT str_string::lenA(VOID) const
{
	if (this->lpstr == NULL) return 0;
	if (this->lpstr_len != 0) return this->lpstr_len;

	return 0;
}

LPSTR str_string::to_lpstr(VOID) const
{
	return this->lpstr;
}

VOID str_string::remove_sequenceA(LPCSTR sequence)
{
	LPSTR ptr;
	if (str::find_sequence_pointerA(this->lpstr, this->lenA(), sequence, str::lenA(sequence),
		&ptr) == ER_STR_NO_SUCH_SEQUENCE) {
		return;
	}

	LPSTR new_buffer = (LPSTR)mem::malloc(this->lenA() - str::lenA(sequence) + str::ASCII_CHAR);
	mem::copy(new_buffer, this->lpstr, (UINT)((DWORD_PTR)ptr - (DWORD_PTR)this->lpstr));

	mem::free(this->lpstr);
	this->lpstr = new_buffer;
	return;
}

std::vector<BYTE> *str_string::convert_to_byte_vector(__in LPCSTR buffer)
{
	std::vector<BYTE> *output = new std::vector<BYTE>();

	for (UINT max = str::lenA(buffer), i = 0; i < max; i += sizeof(WORD)) {
		BYTE raw_byte;
		str::STR_ERROR str_status = str::to_byte(*(PWORD)&buffer[i], &raw_byte);
		if (str_status == str::ER_STR_NO_SUCH_BYTE) {
			delete output;
			return NULL;
		}
		output->push_back(raw_byte);
	}

	return output;
}

// Old functions
str::STR_ERROR str_string::init_string(LPCSTR buffer, LPCWSTR bufferW, UINT size, UINT sizeW, bool perform_conversion)
{

	// Switches and init
	this->convert = perform_conversion;
	this->first_lineW	= NULL;
	this->first_line	= NULL;

	if ((buffer == NULL && bufferW == NULL) || ((size | sizeW) == 0)) return str::ER_STR_GENERAL_FAILURE;


	// raw_buffer is either unicode or ascii
	this->raw_size		= size;
	if (buffer != NULL && size != 0) {
		if (str::lenA(buffer) != size) return str::ER_STR_GENERAL_FAILURE;

		this->raw_buffer	= (LPVOID)mem::malloc(size + str::ASCII_CHAR);
		mem::copy(this->raw_buffer, buffer, size);
		this->raw_type_buffers.ascii		= (LPSTR)mem::malloc(size +str::ASCII_CHAR);
		this->raw_type_buffers.ascii_size	= size;
		mem::copy(this->raw_type_buffers.ascii, buffer, size);
	}
	if (bufferW != NULL && sizeW != 0) {
		if (str::lenW(bufferW) != sizeW) return str::ER_STR_GENERAL_FAILURE;

		this->raw_buffer	= (LPVOID)mem::malloc(sizeW + str::UNICODE_CHAR);
		mem::copy(this->raw_buffer, bufferW, sizeW);
		this->raw_type_buffers.unicode		= (LPWSTR)mem::malloc(sizeW + str::UNICODE_CHAR);
		this->raw_type_buffers.unicode_size	= sizeW;
		mem::copy(this->raw_type_buffers.unicode, bufferW, sizeW);
	}

	// Sets the char type
	if (buffer != NULL) {
		this->is_ascii		= true;
	} 
	if (bufferW != NULL) {
		this->is_unicode	= true;
	}

	// If either unicode, or ascii doesn't exist, create a new buffer for it
	if (perform_conversion == true) {
		if (this->is_ascii == false) {
			this->raw_type_buffers.ascii = str::convert_unicode_to_ascii(bufferW, 
												sizeW, 
												&this->raw_type_buffers.ascii_size);
			if (this->raw_type_buffers.ascii == NULL) return str::ER_STR_NULL;		
			this->is_ascii = true;
		}
		if (this->is_unicode == false) {
			this->raw_type_buffers.unicode = str::convert_ascii_to_unicode(buffer, size,
												&this->raw_type_buffers.unicode_size);
			if (this->raw_type_buffers.unicode == NULL) return str::ER_STR_NULL;
			this->is_unicode = true;
		}
	}

	return str::ER_STR_OK;
}



str::STR_ERROR str_string::blank_line_into_sequence(LPCSTR pattern)
{
	PLINE current_line = this->first_line;
	while (current_line != NULL) {
		if (current_line->line_size < str::lenA("\r\n")) {
			current_line = current_line->next_line;
		}
		if (!str::compareA("\r\n", current_line->line_buffer, str::lenA("\r\n")) && current_line->line_size == str::lenA("\r\n")) {
			str::STR_ERROR status = str_string::update_line_buffer(current_line, pattern, str::lenA(pattern));
		}

		current_line = current_line->next_line;
	}


	return str::ER_STR_OK;
}

str::STR_ERROR str_string::remove_sequence_from_lines(LPCSTR sequence, UINT sequence_size)
{
	PLINE current_line = this->first_line;

	while (current_line != NULL) {

		str_string::remove_sequence_from_line(current_line, sequence, sequence_size);
		current_line = current_line->next_line;
	}

	return str::ER_STR_OK;
}

// This function is not complete...
VOID str_string::remove_sequence_from_line(PLINE line, LPCSTR sequence, UINT sequence_size)
{

	for (UINT i = 0; i < line->line_size; i++) {
		if ((i + sequence_size) > line->line_size) {
			return;
		}

		if (!str::compareA((LPCSTR)((DWORD_PTR)line->line_buffer + i), sequence, sequence_size)) {
			PCHAR	new_buffer = (PCHAR)mem::malloc(line->line_size - sequence_size + 1);
			mem::copy(new_buffer, (LPCVOID)((DWORD_PTR)line->line_buffer), i);
			
			// Anything else to copy?
			if (line->line_size > (i + sequence_size)) {
#ifdef DEBUG_OUT
				DBGOUT("remove_sequence_from_line 0x%08x %d", line->line_buffer, line->line_size);
#endif
			}

			mem::free(line->line_buffer);
			line->line_buffer = new_buffer;
			line->line_size = str::lenA(line->line_buffer);
		}
	}

	return;
}

str::STR_ERROR str_string::update_line_buffer(PLINE string_line, LPCSTR new_string, UINT new_string_length)
{

	if (new_string == NULL || string_line == NULL || new_string_length == 0) return str::ER_STR_UPDATE_LINE_BUFFER;

	mem::free(string_line->line_buffer);
	string_line->line_buffer = (PCHAR)mem::malloc(new_string_length + 1);
	mem::copy(string_line->line_buffer, new_string, new_string_length);
	string_line->line_size   = new_string_length;

	return str::ER_STR_OK;
}

str::STR_ERROR str_string::load_into_lines(LPCSTR default_terminator)
{

	if (default_terminator == NULL || *(PBYTE)default_terminator == '\0') {
		return str::ER_STR_SPLIT_LINES;
	}
	UINT terminator_size = (UINT)str::lenA(default_terminator);
	
	if ((this->raw_type_buffers.unicode == NULL && this->raw_type_buffers.ascii == NULL) || 
		(this->raw_type_buffers.unicode_size == 0 && this->raw_type_buffers.ascii_size == 0)) {
		return str::ER_STR_SPLIT_LINES;
	}

	// Split lines for ascii
	if (this->is_ascii != false) {
		PCHAR current_ptr = (PCHAR)this->raw_type_buffers.ascii;
		if (current_ptr == NULL) {
			return str::ER_STR_SPLIT_LINES;
		}
		PCHAR new_ptr	  = 0;
		while ((DWORD)current_ptr != (DWORD)((DWORD_PTR)this->raw_type_buffers.ascii + this->raw_type_buffers.ascii_size)) {
			str::STR_ERROR status = str::find_sequence_pointerA(current_ptr, this->raw_type_buffers.ascii_size, 
				default_terminator, str::lenA(default_terminator), &new_ptr);

			if (new_ptr == NULL || new_ptr == current_ptr && str::compareA(new_ptr, default_terminator, terminator_size)) {
				// No sequence was found. Either we've reached the end, and there is no such sequence, or this is the only such 
				// line.
				PLINE current_line = this->first_line;
				while (current_line != NULL && current_line->next_line != NULL) current_line = current_line->next_line;

				if (current_line == NULL) {
					this->first_line = (PLINE)mem::malloc(sizeof(LINE));
					current_line = this->first_line;
				} else if (current_line->next_line == NULL) {
					current_line->next_line = (PLINE)mem::malloc(sizeof(LINE));
					current_line = current_line->next_line;
				}

				if (new_ptr != NULL) {
					current_line->line_size = str::lenA(new_ptr);
					current_line->line_buffer = (LPSTR)mem::malloc(current_line->line_size + str::ASCII_CHAR);
					mem::copy(current_line->line_buffer, new_ptr, current_line->line_size);
				} else {
					// new_ptr is null, so a terminator was not found. Check if there is still data
					if (current_ptr[0] == '\0') {
						break;
					} else {
						// No terminator, but there is data. Add a terminator for the sake of consistency
						current_line->line_size = str::lenA(current_ptr) + terminator_size;
						current_line->line_buffer = (LPSTR)mem::malloc(current_line->line_size + str::ASCII_CHAR);
						mem::copy(current_line->line_buffer, current_ptr, str::lenA(current_ptr));
						mem::copy((LPVOID)((DWORD_PTR)current_line->line_buffer + str::lenA(current_ptr)), 
							default_terminator, terminator_size); 
					}
				}
				break;
			}
			
			// Adjust ptr to point to next line
			if (status == str::ER_STR_NO_SUCH_SEQUENCE) {
				new_ptr = (PCHAR)((DWORD_PTR)new_ptr + str::lenA(new_ptr));
			} else {				
				new_ptr = (PCHAR)((DWORD_PTR)new_ptr + str::lenA(default_terminator));
			}

			if (this->first_line == NULL) {

				this->first_line				= (PLINE)mem::malloc(sizeof(LINE));
				if (!this->first_line) return str::ER_STR_SPLIT_LINES;
				this->first_line->line_size		= (UINT)((DWORD_PTR)new_ptr - (DWORD_PTR)current_ptr);
				this->first_line->line_buffer	= (PCHAR)mem::malloc(this->first_line->line_size + str::ASCII_CHAR);
				if (!this->first_line->line_buffer) return str::ER_STR_SPLIT_LINES;
				mem::copy(this->first_line->line_buffer, current_ptr, this->first_line->line_size);

			} else  {
			
				PLINE this_line = this->first_line;
				while (this_line->next_line != NULL) {
					this_line = this_line->next_line;
				}

				this_line->next_line			= (PLINE)mem::malloc(sizeof(LINE));
				if (!this_line->next_line) return str::ER_STR_SPLIT_LINES;
				this_line						= this_line->next_line;

				this_line->line_size			= (UINT)((DWORD_PTR)new_ptr - (DWORD_PTR)current_ptr);
				this_line->line_buffer			= (PCHAR)mem::malloc(this_line->line_size + str::ASCII_CHAR);
				if (!this_line->line_buffer) return str::ER_STR_SPLIT_LINES;
				mem::copy(this_line->line_buffer, current_ptr, this_line->line_size);
			}

			current_ptr = new_ptr;
		}
	}

	// Unicode terminator
	LPWSTR default_terminatorW = str::convert_ascii_to_unicode(default_terminator, str::lenA(default_terminator), NULL);
	UINT terminator_sizeW = str::lenW(default_terminatorW);

	if (this->is_unicode != false) {
		PWCHAR new_ptr, current_ptr = (PWCHAR)this->raw_type_buffers.unicode;
		if (current_ptr == NULL) {
			mem::free(default_terminatorW);
			return str::ER_STR_SPLIT_LINES;
		}
		while((DWORD)current_ptr != (DWORD)((DWORD_PTR)this->raw_type_buffers.unicode + this->raw_type_buffers.unicode_size)) {
			str::STR_ERROR status = str::find_sequence_pointerW(current_ptr, this->raw_type_buffers.unicode_size, 
				default_terminatorW, str::lenW(default_terminatorW), &new_ptr);
			if (new_ptr == NULL || (*new_ptr == '\0')) break;

			if (new_ptr == current_ptr && str::compareW(new_ptr, default_terminatorW, terminator_sizeW)) {
				// No sequence was found. Either we've reached the end, and there is no such sequence, or this is the only such 
				// line.
				PLINEW current_line = this->first_lineW;
				while (current_line != NULL && current_line->next_line != NULL) current_line = current_line->next_line;

				if (current_line == NULL) {
					this->first_lineW = (PLINEW)mem::malloc(sizeof(LINEW));
					current_line = this->first_lineW;
				} else if (current_line->next_line == NULL) {
					current_line->next_line = (PLINEW)mem::malloc(sizeof(LINEW));
					current_line = current_line->next_line;
				}

				
				current_line->line_size = str::lenW(new_ptr);
				current_line->line_buffer = (LPWSTR)mem::malloc(current_line->line_size + str::UNICODE_CHAR);
				mem::copy(current_line->line_buffer, new_ptr, current_line->line_size);

				if (new_ptr != NULL) {
					current_line->line_size = str::lenW(new_ptr);
					current_line->line_buffer = (LPWSTR)mem::malloc(current_line->line_size + str::UNICODE_CHAR);
					mem::copy(current_line->line_buffer, new_ptr, current_line->line_size);
				} else {
					// new_ptr is null, so a terminator was not found. Check if there is still data
					if (current_ptr[0] == '\0') {
						break;
					} else {
						// No terminator, but there is data. Add a terminator for the sake of consistency
						current_line->line_size = str::lenW(current_ptr) + terminator_sizeW;
						current_line->line_buffer = (LPWSTR)mem::malloc(current_line->line_size + str::UNICODE_CHAR);
						mem::copy(current_line->line_buffer, current_ptr, str::lenW(current_ptr));
						mem::copy((LPVOID)((DWORD_PTR)current_line->line_buffer + str::lenW(current_ptr)), 
							default_terminatorW, terminator_sizeW); 
					}
				}

				break;
			}

			if (status == str::ER_STR_NO_SUCH_SEQUENCE) {
				new_ptr = (PWCHAR)((DWORD_PTR)new_ptr + str::lenW(new_ptr));
			} else {				
				new_ptr = (PWCHAR)((DWORD_PTR)new_ptr + str::lenW(default_terminatorW));
			}

			if (this->first_lineW == NULL) {

				this->first_lineW				= (PLINEW)mem::malloc(sizeof(LINEW));
				if (!this->first_lineW) return str::ER_STR_SPLIT_LINES;
				this->first_lineW->line_size	= (UINT)((DWORD_PTR)new_ptr - (DWORD_PTR)current_ptr);
				this->first_lineW->line_buffer	= (PWCHAR)mem::malloc(this->first_lineW->line_size + str::UNICODE_CHAR);
				if (!this->first_lineW->line_buffer) return str::ER_STR_SPLIT_LINES;
				mem::copy(this->first_lineW->line_buffer, current_ptr, this->first_lineW->line_size);

			} else  {
			
				PLINEW this_line = this->first_lineW;
				while (this_line->next_line != NULL) {
					this_line = this_line->next_line;
				}

				this_line->next_line			= (PLINEW)mem::malloc(sizeof(LINEW));
				if (!this_line->next_line) return str::ER_STR_SPLIT_LINES;
				this_line						= this_line->next_line;

				this_line->line_size			= (UINT)((DWORD_PTR)new_ptr - (DWORD_PTR)current_ptr);
				this_line->line_buffer			= (PWCHAR)mem::malloc(this_line->line_size + str::UNICODE_CHAR);
				if (!this_line->line_buffer) return str::ER_STR_SPLIT_LINES;
				mem::copy(this_line->line_buffer, current_ptr, this_line->line_size);
			}

			current_ptr = new_ptr;
		}
	}

	// Set as line split value
	mem::zeromem(&this->line_terminator, sizeof(term_store));
	this->line_terminator.terminator		= (LPSTR)mem::malloc(str::lenA(default_terminator) + str::ASCII_CHAR);
	this->line_terminator.terminator_size	= str::lenA(default_terminator);
	mem::copy(this->line_terminator.terminator, default_terminator, str::lenA(default_terminator));

	return str::ER_STR_OK;
}

str::PLINEW str_string::convert_line_to_lineW(str::PLINE line)
{

	return NULL;
}

str::STR_ERROR str::find_sequence_pointerA(LPCSTR target, UINT target_size, LPCSTR sequence, UINT sequence_size, LPSTR *ptr)
{

	//*ptr = NULL;
	if (ptr != NULL) *ptr = NULL;

	if (target == NULL || sequence == NULL || target_size == 0 || sequence_size == 0) {
		return str::ER_STR_NO_SUCH_SEQUENCE;
	}

	UINT i = 0;
	PBYTE position;
	while (i < target_size) {
		if (*(PCHAR)((DWORD_PTR)target + i) == '\0') {
			return str::ER_STR_NO_SUCH_SEQUENCE;
		}
		if ((i > (target_size + sequence_size))) {
			return str::ER_STR_NO_SUCH_SEQUENCE;
		}

		if (!mem::compare((LPCSTR)((DWORD_PTR)target + i), sequence, sequence_size)) {
			position = (PBYTE)((DWORD_PTR)target + i);
			if (ptr != NULL) *ptr = (LPSTR)position;
			return str::ER_STR_OK;
		}
		i++;
	}

	return str::ER_STR_NO_SUCH_SEQUENCE;
}

str::STR_ERROR str::find_sequence_pointerW(LPCWSTR target, UINT target_size, LPCWSTR sequence, UINT sequence_size, LPWSTR *ptr)
{
	*ptr = (LPWSTR)target;

	if (target == NULL || sequence == NULL || target_size == 0 || sequence_size == 0 || ptr == NULL) {
		return str::ER_STR_NO_SUCH_SEQUENCE;
	}

	UINT i = 0;
	UINT tmp_size = target_size / str::UNICODE_CHAR;
	while (i < tmp_size) {
		if (target[i] == '\0') return str::ER_STR_NO_SUCH_SEQUENCE;
		if ((i > (tmp_size + sequence_size))) return str::ER_STR_NO_SUCH_SEQUENCE;

		if (!mem::compare((LPCVOID)&target[i], sequence, sequence_size)) { // fixme
			*ptr = (LPWSTR)&target[i];
			return str::ER_STR_OK;
		}

		i++;
	}

	return str::ER_STR_SPLIT_LINES;
}

UINT str::lenA(LPCSTR input_string)
{
	UINT			out_length = 0;
	PCHAR			ptr;

	ptr				= (PCHAR)input_string;
	out_length		= 0;
	while (*ptr != 0) {
		out_length++;
		ptr++;
	}

	return out_length;
}

UINT str::lenW(LPCWSTR input_string)
{
	UINT			out_length = 0;
	PWCHAR			ptr;

	ptr				= (PWCHAR)input_string;
	while (*ptr != 0) {
		out_length++;
		ptr++;
	}

	return out_length * 2;
}

UINT str::string_to_intA(LPCSTR input_string)
{
	INT num = 0;
	CHAR digit;
	while ((digit = *input_string++) != '\0') {
		if (digit < '0' || digit > '9') {
			return num;  /* No valid conversion possible */
		}	
		num *= 10;
		num += digit - '0';
	}
	return num;
}

LPSTR str::int_to_stringA(__in UINT number)
{
	LPSTR buffer = (LPSTR)mem::malloc(max_32bit_int_string);
	sprintf_s(buffer, max_32bit_int_string, "%d", number);

	return buffer;
}

BOOL str::compareA(LPCSTR string1, LPCSTR string2, UINT max_length)
{
	UINT			i;

	//if (str::lenA(string1) != str::lenA(string2)) return 1;

	for (i = 0; i < max_length; i++) {
		if (string1[i] != string2[i]) {
			return 1;
		}
	}

	return 0;
}

BOOL str::compareW(LPCWSTR string1, LPCWSTR string2, UINT max_length)
{
	UINT			i;

	for (i = 0; i < max_length; i++) {
		if (string1[i] != string2[i]) {
			return 1;
		}
	}

	return 0;
}

LPSTR str::find_filename_from_path(LPCSTR path)
{
	if (path == NULL) return NULL;
	PBYTE ptr;

	ptr = (PBYTE)((DWORD_PTR)path + str::lenA(path));
	while (*(PBYTE)((DWORD_PTR)ptr - 1) != '\\') {
		ptr--;
	}

	return (LPSTR)ptr;
}

VOID str::strcpyA(LPSTR dest, LPCSTR src, UINT size)
{
	UINT			i;

	for (i = 0; i < size; i++) {
		//if (*(PBYTE)((DWORD_PTR)dest + i) == '\0' || *(PBYTE)((DWORD_PTR)src + i) == '\0') break;
		*(PBYTE)((DWORD_PTR)dest + i) = *(PBYTE)((DWORD_PTR)src + i);
	}

	return;
}

str::PLINE str_string::get_first_line(VOID)
{
	if (this->first_line == NULL) return NULL;
	return this->first_line;
}

LPSTR str_string::get_first_line_buffer(VOID)
{
	if (this->get_first_line() == NULL) {
		return NULL;
	} else {
		return this->get_first_line()->line_buffer;
	}
}


VOID str_string::cleanup(VOID)
{

	// Clean up lines
	if (this->is_ascii) {
		PLINE tmp_line = this->first_line;
		while (tmp_line != NULL) {
			mem::free(tmp_line->line_buffer);
			tmp_line->line_size = 0;
			PLINE tmp_line2 = tmp_line->next_line;
			mem::free(tmp_line);
			tmp_line = tmp_line2;
		}

		mem::free(this->raw_type_buffers.ascii);
	}

	if (this->is_unicode) {
		PLINEW tmp_line = this->first_lineW;
		while (tmp_line != NULL) {
			mem::free(tmp_line->line_buffer);
			tmp_line->line_size = 0;
			PLINEW tmp_line2 = tmp_line->next_line;
			mem::free(tmp_line);
			tmp_line = tmp_line2;
		}

		mem::free(this->raw_type_buffers.unicode);
	}

	// Release raw buffers
	mem::free(this->raw_buffer);
	this->raw_size = 0;

	return;
}

// We can go through all the line buffers in specific. this prepares the class for that
LPSTR str_string::set_next_line(VOID)
{
	this->get_line_buffers_line = NULL;
	this->get_line_buffers_line = this->first_line;

	return get_line_buffers_line->line_buffer;
}

LPSTR str_string::get_new_line_buffer(VOID)
{
	PLINE tmp_line = this->get_line_buffers_line;
	tmp_line = tmp_line->next_line;
	if (tmp_line == NULL) return NULL;

	this->get_line_buffers_line = tmp_line;
	return tmp_line->line_buffer;
}

LPWSTR str::convert_ascii_to_unicode(	__in LPCSTR ascii_string,
										__in UINT ascii_string_size,
										__out PUINT unicode_string_size)
{
	if (ascii_string == NULL || ascii_string_size == 0) return NULL;

	UINT new_unicode_string_size = (UINT)(ascii_string_size * str::UNICODE_CHAR);
	if (new_unicode_string_size == 0) return NULL;

	LPWSTR	new_unicode_string = (LPWSTR)mem::malloc(new_unicode_string_size + str::UNICODE_CHAR);
	if (new_unicode_string == NULL) return NULL;
	PCHAR	ptrA = (PCHAR)ascii_string;
	PTCHAR	ptrW = (PTCHAR)new_unicode_string;
	for (UINT i = 0; i < ascii_string_size; i++) {

		*ptrW = (WCHAR)*ptrA;

		ptrA++;
		ptrW++;
	}

	if (unicode_string_size != NULL) *unicode_string_size = new_unicode_string_size;
	return new_unicode_string;
}

LPSTR str::convert_unicode_to_ascii(	__in LPCWSTR unicode_string, 
										__in UINT unicode_string_size, 
										__out PUINT ascii_string_size)
{
	if (unicode_string == NULL || unicode_string_size == 0) return NULL;

	UINT	new_ascii_string_size = (UINT)(unicode_string_size / str::UNICODE_CHAR);
	if (new_ascii_string_size == 0) return NULL;

	LPSTR	new_ascii_string = (LPSTR)mem::malloc(new_ascii_string_size + str::ASCII_CHAR);
	if (new_ascii_string == NULL) return NULL;
	PCHAR	ptrA = new_ascii_string;
	PTCHAR	ptrW = (PTCHAR)unicode_string;
	for (UINT i = 0; i < new_ascii_string_size; i++) {
		
		*ptrA = (CHAR)*ptrW;

		ptrA++;
		ptrW++;
	}

	if (ascii_string_size != NULL) *ascii_string_size = new_ascii_string_size;
	return new_ascii_string;
}

str::STR_ERROR str_string::remove_commentsA(LPCSTR sequence)
{

	if (this->is_ascii == FALSE) return str::ER_STR_REMOVE_COMMENTS;

	PLINE		current_line = (PLINE)this->get_first_line();

	// Remove lines beginning with a comment
	while (current_line != NULL) {

		if (current_line->line_buffer[0] == *(PCHAR)sequence) {
			// Remove the whole line
			str::STR_ERROR status = remove_lineA((PLINE)this->get_first_line(), current_line);
			if (status != str::ER_STR_OK) return str::ER_STR_REMOVE_COMMENTS;

			current_line = (PLINE)this->get_first_line();
			continue;
		}

		current_line = current_line->next_line;
	}

	// Remove all sequences after the comment
	UINT sequence_size = str::lenA(sequence);
	current_line = this->get_first_line();
	while (current_line != NULL) {
		LPSTR ptr = NULL;
		if (str::find_sequence_pointerA(current_line->line_buffer, current_line->line_size, sequence, sequence_size, &ptr) ==
			ER_STR_NO_SUCH_SEQUENCE) {
				current_line = current_line->next_line;
				continue;
		}

		OFFSET32 offset = (OFFSET32)((DWORD_PTR)ptr - (DWORD_PTR)current_line->line_buffer);
		LPSTR new_string = (LPSTR)mem::malloc(offset + str::ASCII_CHAR);
		mem::copy(new_string, current_line->line_buffer, offset);
		UINT new_string_size = str::lenA(new_string);
		update_line_buffer(current_line, new_string, new_string_size);
	}

	return str::ER_STR_OK;
}

str::STR_ERROR str_string::remove_lineA(PLINE first_line, PLINE line)
{

	if (first_line == NULL || line == NULL) return str::ER_STR_GENERAL_FAILURE;

	if (first_line == line) {
		PLINE tmp_line = first_line->next_line;
		mem::free(first_line->line_buffer);
		mem::free(first_line);
		this->first_line = tmp_line;
		
		return str::ER_STR_OK;
	}

	PLINE tmp_line = first_line;
	while ((PLINE)(tmp_line->next_line) != line) tmp_line = tmp_line->next_line;
	
	PLINE tmp_line2 = tmp_line->next_line;
	tmp_line->next_line = tmp_line2->next_line;
	mem::free(tmp_line2->line_buffer);
	mem::free(tmp_line2);

	return str::ER_STR_OK;
}

str::STR_ERROR str::set_pointer_to_after_sequence(LPCSTR string, LPCSTR sequence, UINT sequence_length, PCHAR *ptr)
{
	if (string == NULL || sequence == NULL || sequence_length == 0 || ptr == NULL) return str::ER_STR_SET_PTR_TO_AFTER_SEQUENCE;

	PCHAR tmp = (PCHAR)string;

	if (sequence_length == sizeof(BYTE)) {

		BYTE seq = *sequence;

		while (*tmp != '\0') {

			if (seq == *tmp) {
				*ptr = (PCHAR)&tmp[1];
				if (*ptr == '\0') {
					*ptr = NULL;
				}
				return str::ER_STR_OK;
			}

			tmp++;
		}

	} else {
		DebugBreak();
		PCHAR tmp = "set_pointer_function";
	}



	return str::ER_STR_OK;
}

bool str::find_character_in_stringA(LPCSTR string, UINT string_length, CHAR character)
{
	if (string == NULL || string_length == 0) return false;

	PCHAR ptr = (PCHAR)string;
	for (UINT i = 0; i < string_length; i++) {

		if (ptr[i] == '\0') return false;

		if (ptr[i] == character) return true;
	}

	return false;
}

LPSTR str_string::convert_lines_to_string(str::PLINE first_line, PUINT string_size, LPCSTR terminator, UINT terminator_size)
{
	if (first_line == NULL) return NULL;

	// Get size
	*string_size = 0;
	PLINE current_line = first_line;
	while (current_line != NULL) {

		if (current_line->line_buffer == NULL || current_line->line_size == 0) {
			return NULL;
		}

		*string_size += current_line->line_size + terminator_size;

		current_line = current_line->next_line;
	}
	if (*string_size == 0) return NULL;

	LPSTR string = (LPSTR)mem::malloc(*string_size + str::ASCII_CHAR);
	current_line = first_line;
	PCHAR ptr = (PCHAR)string;
	while (current_line != NULL) {
		mem::copy(ptr, current_line->line_buffer, current_line->line_size);
		ptr = &ptr[current_line->line_size];

		if (terminator_size > 0) {
			mem::copy(ptr, (LPCVOID)terminator, terminator_size);
			ptr = &ptr[terminator_size];
		}
	}

	return string;
}

LPSTR str_string::get_type_buffersA(PUINT buffer_size)
{
	if (this->raw_type_buffers.ascii == NULL || this->raw_type_buffers.ascii_size == 0) return NULL;

	*buffer_size = this->raw_type_buffers.ascii_size;
	return this->raw_type_buffers.ascii;
}

LPSTR str_string::get_term_store(PUINT size)
{
	if (this->line_terminator.terminator == NULL || this->line_terminator.terminator_size == 0) return NULL;

	*size = this->line_terminator.terminator_size;
	return this->line_terminator.terminator;
}

LPSTR str::pathcombineA(__in LPCSTR path1, __in LPCSTR path2)
{
	if (path1 == NULL || path2 == NULL) return NULL;

	static const UCHAR directory_slash = '\\';

	LPSTR out;
	UINT path1_size = str::lenA(path1);
	UINT path2_size = str::lenA(path2);

	if (path1_size == 0 || path2_size == 0) return NULL;
	
	// Check for "/"
	if (path1[path1_size] != directory_slash) {

		out = (LPSTR)mem::malloc(path1_size + path2_size + sizeof(directory_slash) + str::ASCII_CHAR);
		mem::copy(out, path1, path1_size);
		out[path1_size] = directory_slash;
		mem::copy((LPVOID)((DWORD_PTR)out + path1_size + sizeof(directory_slash)), path2, path2_size);
	} else {
		out = (LPSTR)mem::malloc(path1_size + path2_size + str::ASCII_CHAR);
		mem::copy(out, path1, path1_size);
		mem::copy((LPVOID)((DWORD_PTR)out + path1_size), path2, path2_size);
	}

	return out;
}

str::STR_ERROR str_string::remove_blank_linesA(VOID)
{
	if (this->first_line == NULL) return str::ER_STR_OK;

	PLINE current_line = this->first_line;
	while (current_line != NULL) {
		if (current_line->line_buffer[0] == '\0') {
			remove_lineA(this->first_line, current_line);
			current_line = this->first_line;
			continue;
		}
		current_line = current_line->next_line;
	}

	return str::ER_STR_OK;
}

bool str::is_digitA(LPCSTR buffer, UINT buffer_len)
{
	PBYTE ptr = (PBYTE)buffer;
	for (UINT i = 0; i < buffer_len; i++) {
		if (!(ptr[i] >= 0x30 && ptr[i] <= 0x39)) return false;
	}

	return true;
}

bool str::is_charA(LPCSTR buffer, UINT len)
{
	PBYTE ptr = (PBYTE)buffer;
	for (UINT i = 0; i < len; i++) {

		if (ptr[i] == '\0') {
			return false;
		}

		if (!(ptr[i] >= 0x20 && ptr[i] <= 0x127)) {
			if ((ptr[i] == str::term_carriage) || (ptr[i] == str::term_newline)) {
				continue;
			} else if (ptr[i] == '\\') {
				continue;
			}

			return false;
		}
	}

	return true;
}

std::vector<LPSTR> *str_string::split_string_by_terminatorA(
	__inopt const str_string *buffer, __in const LPSTR term, __in const UINT term_len) const
{
	std::vector<LPSTR> *string_array = new std::vector<LPSTR>();
	const str_string *target_buffer;
	if (buffer == NULL) {
		target_buffer = this;
	} else {
		target_buffer = const_cast<str_string *>(buffer);
	}

	PCHAR start = target_buffer->to_lpstr();
	while (TRUE) {
		PCHAR end;
		if (str::find_sequence_pointerA(start, str::lenA(start),
			term, term_len, &end) == ER_STR_NO_SUCH_SEQUENCE) {

			if (start[0] != '\0') {
				// This is the end
				LPSTR buffer = (LPSTR)mem::malloc(str::lenA(start) + str::ASCII_CHAR);
				mem::copy(buffer, start, str::lenA(start));
				string_array->push_back(buffer);
			}

			return string_array;
		}
		LPSTR buffer = (LPSTR)mem::malloc((DWORD_PTR)end - (DWORD_PTR)start + str::ASCII_CHAR);
		mem::copy(buffer, start, (DWORD_PTR)end - (DWORD_PTR)start);
		string_array->push_back(buffer);
		end += term_len;
		start = end;
	}
	
	return string_array;
}

std::vector<str_string *> *str_string::split_string_by_terminatorA_(
	__inopt const str_string *buffer, __in const LPSTR term, __in const UINT term_len) const
{
	std::vector<str_string *> *string_array = new std::vector<str_string *>();
	const str_string *target_buffer;
	if (buffer == NULL) {
		target_buffer = this;
	} else {
		target_buffer = const_cast<str_string *>(buffer);
	}

	PCHAR start = target_buffer->to_lpstr();
	while (TRUE) {
		PCHAR end;
		if (str::find_sequence_pointerA(start, str::lenA(start),
			term, term_len, &end) == ER_STR_NO_SUCH_SEQUENCE) {

			if (start[0] != '\0') {
				// This is the end
				LPSTR buffer = (LPSTR)mem::malloc(str::lenA(start) + str::ASCII_CHAR);
				mem::copy(buffer, start, str::lenA(start));
				string_array->push_back(new str_string(buffer));
				mem::free(buffer);
			}

			return string_array;
		}
		LPSTR buffer = (LPSTR)mem::malloc((DWORD_PTR)end - (DWORD_PTR)start + str::ASCII_CHAR);
		mem::copy(buffer, start, (DWORD_PTR)end - (DWORD_PTR)start);
		string_array->push_back(new str_string(buffer));
		mem::free(buffer);
		end += term_len;
		start = end;
	}	 

	return string_array;
}


// Removes ALL instances of the sequence (not yet implemented). Does not free buffer. Returns NULL if no sequence is found.
VOID str::remove_sequence_from_buffer_realloc(LPSTR buffer, UINT buffer_size, LPCSTR sequence, 
	UINT sequence_size, LPSTR *new_buffer, PUINT new_buffer_size)
{
	if (buffer == NULL || sequence == NULL) return;

	*new_buffer = NULL;
	*new_buffer_size = 0;

	LPSTR ptr;
	if (str::find_sequence_pointerA(buffer, buffer_size, sequence, sequence_size, &ptr) == ER_STR_NO_SUCH_SEQUENCE) {
		// Sequence was not found.
		return;
	}
	LPSTR out_buffer = (LPSTR)mem::malloc(buffer_size - sequence_size + str::ASCII_CHAR);
	*new_buffer_size = buffer_size - sequence_size + str::ASCII_CHAR;
	if ((DWORD_PTR)ptr == (DWORD_PTR)buffer) {
		mem::copy(out_buffer, &buffer[sequence_size], (DWORD_PTR)buffer_size - (DWORD_PTR)sequence_size);
	} else {
		mem::copy(out_buffer, buffer, (UINT)((DWORD_PTR)ptr - (DWORD_PTR)buffer));
		mem::copy(&out_buffer[str::lenA(out_buffer)], &ptr[sequence_size], str::lenA(&ptr[sequence_size]));
	}
	
	*new_buffer = out_buffer;
	mem::free(buffer);

	return;
}

STR_ERROR str::ascii_to_short(__inout PBYTE input)
{
	if (*input >= 0x30 && *input <= 0x39) { // 0-9
		*input -= 0x30;
	} else if (*input >= 0x41 && *input <= 0x5a) { //A-Z
		*input -= 0x37;
	} else if (*input >= 0x61 && *input <= 0x66) { //a-f
		*input -= 0x57;
	} else {
		return ER_STR_NO_SUCH_BYTE;
	}

	return ER_STR_OK;
}

str::STR_ERROR str::to_byte(__in const WORD string_character, __out PBYTE string_byte)
{
	BYTE output = (BYTE)string_character;
	STR_ERROR convert_status = str::ascii_to_short(&output);
	if (convert_status == ER_STR_NO_SUCH_BYTE) {
		return convert_status;
	}
	BYTE second_byte = string_character >> 8;
	convert_status = str::ascii_to_short(&second_byte);
	*string_byte = (output << 4) + second_byte;

	return ER_STR_OK;
}


VOID str_string::add_line_(__in str_string *current_line, __in str_string *terminator) 
{
	if (current_line == NULL) return;
	if (this->vectored_lines == NULL) vectored_lines = new std::vector<line *>;

	this->vectored_lines->push_back(new line(current_line, terminator));
}

extern "C"
VOID str_string::add_line(__in LPCSTR buffer, __inopt LPCSTR terminator)
{
	if (buffer == NULL) return;

	PLINE new_line			= (PLINE)mem::malloc(sizeof(LINE));
	new_line->line_buffer	= (LPSTR)mem::malloc(str::lenA(buffer));
	new_line->line_size		= str::lenA(buffer);
	
	PLINE current_line		= this->first_line;
	while (current_line->next_line != NULL) current_line = current_line->next_line;

	current_line			= new_line;
	return;
}

// Returns a new str_string with all vectored lines concatenated
str_string *str_string::to_lpstr_lines_(VOID)
{
	str_string *output_string = new str_string();
	for (UINT i = 0; i < this->vectored_lines->size(); i++) {
		LPSTR buffer;
		UINT buffer_size;
		this->vectored_lines->at(i)->get_full_buffer(&buffer, &buffer_size);
		output_string->add_to_append(buffer);
	}	
	return output_string;
}

BYTE str::ascii_word_to_byte(__in const WORD sequence)
{
	BYTE out = 0;
	BYTE tmp = (BYTE)sequence;
	for (UINT i = 0; i < 2; i++) {

		if (tmp >= 0x41 && tmp <= 0x5a) {
			if (i == 0) {
				out = tmp - 0x37;
				out = out << 4;
			} else {
				out = (tmp - 0x37) | out;
				break;
			}
		} else if (tmp >= 0x30 && tmp <= 0x39) {
			if (i == 0) {
				out = tmp - 0x30;
				out = out << 4;
			} else {
				out = (tmp - 0x30) | out;
				break;
			}
		} else if (tmp >= 0x61 && tmp <= 0x7a) {
			DebugBreak();
		}

		tmp = (BYTE)((sequence & 0xff00) >> 8);
	}

	return out;
}

std::vector<BYTE> *str::string_to_byte_vector(__in const LPSTR input_string)
{
	if (input_string == NULL) {
		return NULL;
	}

	std::vector<BYTE> *out_array = new std::vector<BYTE>;
	PWORD ptr = (PWORD)input_string;
	UINT string_size = str::lenA(input_string) / 2;
	
	for (UINT i = 0; i < string_size; i++, ptr++) {
		out_array->push_back(ascii_word_to_byte(*ptr));
	}


	return out_array;
}

WORD str::convert_byte_to_ascii_word(__in const BYTE input)
{
	WORD out_word;

	BYTE tmp = (input & 0xf0) >> 4;
	if (tmp < 0x0a) {
		tmp += 0x30;
	} else {
		tmp += 0x40 - 9;
	}

	out_word = tmp;

	tmp = (input & 0x0f);
	if (tmp < 0x0a) {
		tmp += 0x30;
	} else {
		tmp += 0x40 - 9;
	}

	out_word = out_word | (tmp << 8);

	return out_word;
}

// Converts an std::vector<BYTE> to an str_string in ASCII
str_string *str::byte_vector_to_string(__in std::vector<BYTE>& byte_array)
{
	if (byte_array.size() == 0) {
		return NULL;
	}

	LPSTR out_buffer = (LPSTR)mem::malloc((byte_array.size() * 2) + str::ASCII_CHAR);

	PWORD ptr = (PWORD)out_buffer;
	for (std::vector<BYTE>::iterator i = byte_array.begin(); i != byte_array.end(); i++, ptr++) {
		*ptr = convert_byte_to_ascii_word(*i);
	}

	str_string *out_string = new str_string(out_buffer);
	mem::free(out_buffer);

	return out_string;
}


// Clears lines and strings, and adds in a new string
bool str_string::add_new_string(__in const LPSTR input_string, __in const UINT input_string_size)
{
	this->is_ascii = false;


	if (input_string[0] == '\0' || str::lenA(input_string) != input_string_size) {
		return false;
	}

	if (this->is_unicode == true) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Unicode not supported in add_new_strings()");
#endif
		return true;
	}

	if (this->first_line != NULL || this->current_line != 0) {
		//FIXME
#ifdef DEBUG_OUT
		DBGOUT("[!] str_string: add_new_string to valid first_line objects\n");
#endif
		return false;
	}

	if (this->lpstr != NULL && this->lpstr_len != 0) {
		if (str::lenA(this->lpstr) != this->lpstr_len) {
			return false;
		}

		mem::free(this->lpstr);
		this->lpstr			= NULL;
		this->lpstr_len		= 0;
	}

	this->lpstr			= (LPSTR)mem::malloc(input_string_size + str::ASCII_CHAR);
	this->lpstr_len		= input_string_size;
	mem::copy(this->lpstr, input_string, input_string_size);
	this->is_ascii		= true;

	return true;
}