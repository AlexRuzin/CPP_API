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
#pragma message (OUTPUT_PRIMARY "str: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "str: Compiling 32-bit.")
#endif
#endif

#include "common/mem.h"

#include "debug/assert.h"
#include "debug/error.h"

#pragma once

class str_string;

namespace str
{
	typedef UINT STR_ERROR;

	enum {
		ER_STR_OK,
		ER_STR_GENERAL_FAILURE,
		ER_STR_NULL,
		ER_STR_SPLIT_LINES,
		ER_STR_NO_SUCH_SEQUENCE,
		ER_STR_BLANK_LINE_SEQUENCE,
		ER_STR_UPDATE_LINE_BUFFER,
		ER_STR_REMOVE_COMMENTS,
		ER_STR_SET_PTR_TO_AFTER_SEQUENCE,
		ER_STR_NO_SUCH_BYTE
	};

	// Lines
	typedef struct line {
		PCHAR line_buffer;
		UINT  line_size;
		line  *next_line;
	} LINE, *PLINE;

	typedef struct lineW {
		LPWSTR	line_buffer;
		UINT	line_size;
		lineW	*next_line;
	} LINEW, *PLINEW;

	// Various constants
	const UINT UNICODE_CHAR = 2;
	const UINT UNICODE_TERM = UNICODE_CHAR;
	const UINT ASCII_CHAR	= 1;
	const UINT ASCII_TERM	= ASCII_CHAR;

	// Types
	//typedef WORD TCHAR;
	//typedef PWORD PTCHAR;

	// Default windows carriage return/new line
	static const LPSTR carriage_return = "\r\n";
	static const CHAR term_carriage = '\r';
	static const CHAR term_newline = '\n';

	// Get string length ASCII
	UINT lenA(LPCSTR input_string);

	// Get string length UNICODE
	UINT lenW(LPCWSTR input_string);

	// Compare two strings ASCII
	BOOL compareA(LPCSTR string1, LPCSTR string2, UINT max_length);
	BOOL compareW(LPCWSTR string1, LPCWSTR string2, UINT max_length);

	// Returns a pointer to the filename in a full path
	LPSTR find_filename_from_path(LPCSTR path);

	// Copies a string
	VOID strcpyA(LPSTR dest, LPCSTR src, UINT size);

	// Finds an ASCII sequence in a string
	str::STR_ERROR find_sequence_pointerA(LPCSTR target, UINT target_size, LPCSTR sequence, 
		UINT sequence_size, LPSTR *ptr);

	// Finds an UNICODE sequence
	str::STR_ERROR find_sequence_pointerW(LPCWSTR target, UINT target_size, LPCWSTR sequence, 
		UINT sequence_size, LPWSTR *ptr);

	// Converts a string to an int.
	UINT string_to_intA(LPCSTR input_string);

	// Converts a int to a string
	static const UINT max_32bit_int_string = 16;
	LPSTR int_to_stringA(__in UINT number);

	// Converts unicode to ascii, returns a new buffer
	LPSTR convert_unicode_to_ascii(		__in LPCWSTR unicode_string, 
										__in UINT unicode_string_size, 
										__out PUINT ascii_string_size);

	// Converts ascii to unicode
	LPWSTR convert_ascii_to_unicode(	__in LPCSTR ascii_string,
										__in UINT ascii_string_size,
										__out PUINT unicode_string_size);

	// Sets ptr to the string after the sequence. If it is 0, ptr will be null
	str::STR_ERROR set_pointer_to_after_sequence(LPCSTR string, LPCSTR sequence, UINT sequence_length, PCHAR *ptr);

	// Looks for a character in a string ASCII
	bool find_character_in_stringA(LPCSTR string, UINT string_length, CHAR character);

	// Combines paths
	LPSTR pathcombineA(__in LPCSTR path1, __in LPCSTR path2);

	// Checks for ASCII digits
	bool is_digitA(LPCSTR buffer, UINT buffer_len);

	// Check for ASCII characters
	bool is_charA(LPCSTR buffer, UINT len);

	// Removes a sequence from a buffer and reallocates it
	VOID remove_sequence_from_buffer_realloc(LPSTR buffer, 
		UINT buffer_size, LPCSTR sequence, 
		UINT sequence_size, LPSTR *new_buffer, PUINT new_buffer_size);

	STR_ERROR to_byte(__in const WORD string_character, __out PBYTE string_byte);

	STR_ERROR ascii_to_short(__inout PBYTE input);

	// converts an std::vector<BYTE> to a str_string (ASCII)
	str_string *byte_vector_to_string(__in std::vector<BYTE>& byte_array);
	WORD convert_byte_to_ascii_word(__in const BYTE input);

	// Note: this is a crazy function. It doesn't check anything and expects proper input
	std::vector<BYTE> *string_to_byte_vector(__in const LPSTR input_string);
	BYTE ascii_word_to_byte(__in const WORD sequence);

	// v2.0 style string /////////////////////////////////////////////////////////
	//class string;
	//typedef Ptr<string> String;
	//typedef std::shared_ptr<string> String;
	//typedef std::unique_ptr<string> StringUnique;

	class string {
	private:
		Ptr<LPSTR>							raw_buffer;				// Data is copied upon init
		UINT								raw_buffer_size;
		
		typedef CHAR ELEMENT, *PELEMENT;
		static const ELEMENT element_new_line = (ELEMENT)str::term_newline;
		static const ELEMENT element_carriage = (ELEMENT)str::term_carriage;

		class element;
		typedef Ptr<element>				Element;
		typedef Ptr<std::vector<Element *>>	ElementArray;
		ElementArray						ElementArrayRaw; // This is the entire raw input
		
		class line;
		typedef Ptr<line>					Line;
		typedef Ptr<std::vector<Line *>>	LineArray;
		LineArray							LineArrayRaw; // Lines
		
		// Character element class
		class element {
		private:
			ELEMENT		value;
			UINT		number_of_elements;

			static const ELEMENT invalid_char	= -1;
			static const UINT no_elements		= 0;
			static const UINT one_element		= 1;

		public:
			element(__in const ELEMENT character) :
				value(character),
				number_of_elements(one_element)
				{

				}

			element(VOID) :
				value(invalid_char),
				number_of_elements(no_elements)
				{

				}
			~element(VOID)
			{
				value = invalid_char;
			}

			ELEMENT get(VOID) const
			{
				return value;
			}
		};

		// Character line class
		class line {
		private:
			ElementArray	Elements;

		public:
			line(VOID)
			{

			}
			line(__in Ptr<std::vector<Element *>> input) :
				Elements(new std::vector<Element *>(input->size()))
				{
					for (std::vector<Element *>::iterator o = Elements->begin(),
						i = input->begin();
						o != Elements->end(); i++, o++) {

						**o = new element((**i)->get());
					}
				}
			~line(VOID)
			{
				DebugBreak();
			}
		};

	public:
		string(VOID) :
			ElementArrayRaw(new std::vector<Element *>()),
			LineArrayRaw(new std::vector<Line *>()),
			raw_buffer(NULL), raw_buffer_size(0),
			lpstr_buffer(NULL), lpstr_buffer_size(0)
			{
				DebugBreak();
			}

		string(__in const LPSTR input) :
			ElementArrayRaw(new std::vector<Element *>),
			LineArrayRaw(NULL),
			raw_buffer(NULL),
			lpstr_buffer(NULL), lpstr_buffer_size(0)
			{
				//ElementArrayRaw->resize(str::lenA(input));
				LineArrayRaw	= new std::vector<Line *>;

				raw_buffer_size			= str::lenA(input);
				LPSTR raw_buffer_new	= (LPSTR)mem::malloc(raw_buffer_size + str::ASCII_CHAR);
				mem::copy(raw_buffer_new, input, raw_buffer_size);
				raw_buffer = &raw_buffer_new;

				PELEMENT ptr = (PELEMENT)*raw_buffer;
				for (UINT i = 0; i < raw_buffer_size; ptr++, i++) {

					//this->ElementArrayRaw->push_back(*new_element);
				}

				// Generate lines, even if there is only one line
				for (std::vector<Element *>::iterator i = ElementArrayRaw->begin(); 
					i != ElementArrayRaw->end(); i++) {

					if ((**i)->get() == element_carriage) {
						i += 2;
						if (i == ElementArrayRaw->end()) {
							break;
						}
					}
				}

				if (LineArrayRaw->size() == 0) {
					// No terminators, create only one line
					//Line new_line(ElementArrayRaw);
					//LineArrayRaw->push_back(Line(*ElementArrayRaw));
				}
			}

		~string(VOID)
		{
			if (lpstr_buffer != NULL) mem::free(lpstr_buffer);
		}

		string& operator=(const string& o)
		{
			DebugBreak();
		}

		string& operator=(const LPSTR o)
		{
			if (o == NULL) {
				raw_buffer.clear_(&raw_buffer);
				ElementArrayRaw.clear_(&ElementArrayRaw);
				LineArrayRaw.clear_(&LineArrayRaw);

				return *this;
			}



			return *this;
		}

	private:
		LPSTR		lpstr_buffer;
		UINT		lpstr_buffer_size;
	public:
		LPSTR* operator->(VOID)
		{
			if (lpstr_buffer != NULL) {
				return &lpstr_buffer;
			}

			if (this->raw_buffer_size == 0) return NULL;

			this->lpstr_buffer = (LPSTR)mem::malloc(this->raw_buffer_size + str::ASCII_CHAR);
			mem::copy(this->lpstr_buffer, *this->raw_buffer, this->raw_buffer_size);

			return &lpstr_buffer;
		}
	};
};

typedef Ptr<str::string> String;

using namespace str;

#ifndef str_string
class str_string;
typedef Ptr<str_string> StrString;
class str_string {

	typedef struct byte_char {
		UCHAR		character;
		WORD		unicode_character;
	} BYTE_CHAR, *PBYTE_CHAR;

	// Type buffers. These buffers contain info on BOTH ASCII and UNICODE
	typedef struct type_buffers {
		LPSTR		ascii;
		LPWSTR		unicode;
		UINT		ascii_size;
		UINT		unicode_size;
	};

	// This is the terminator used to split lines
	typedef struct term_store {
		LPSTR		terminator;
		UINT		terminator_size;
	};
	term_store		line_terminator;

	class line {
	private:
		LPSTR		line_buffer;
		LPSTR		line_terminator;

		UINT		line_buffer_size;
		UINT		line_terminator_size;

		str_string	*line_string;
		str_string	*line_terminator_string;

		bool		is_terminator;

		LPSTR		complete_buffer;
		UINT		complete_buffer_size;
	public:
		// v2.0 Ctors
		line(__in str_string *buffer, __in str_string *terminator) :
			line_buffer(buffer->to_lpstr()),
			line_buffer_size(buffer->lenA()),
			is_terminator(true),
			line_terminator(NULL),
			line_terminator_size(0),
			line_string(line_string), line_terminator_string(line_terminator_string)
			{
				if (terminator != NULL) {
					line_terminator = terminator->to_lpstr();
					line_terminator_size = terminator->lenA();
				}
			}

		// C-style ctors
		line(__in LPCSTR buffer, __in LPCSTR terminator) :
			line_buffer((LPSTR)buffer),
			line_buffer_size(str::lenA(buffer)),
			is_terminator(true),
			line_terminator((LPSTR)terminator),
			line_terminator_size(str::lenA(terminator)),
			line_string(NULL), line_terminator_string(NULL)
			{

			}
		line(__in LPCSTR buffer) :
			line_buffer((LPSTR)buffer),
			line_buffer_size(str::lenA(buffer)),
			is_terminator(false),
			line_terminator(NULL),
			line_terminator_size(0),
			line_string(NULL), line_terminator_string(NULL)
			{

			}


		~line(VOID)
		{
			mem::free(line_buffer);
			if (complete_buffer != NULL) mem::free(complete_buffer);
		}

		VOID line::get_full_buffer(__out LPSTR *buffer, __out PUINT buffer_size) 
		{
			this->complete_buffer = (LPSTR)mem::malloc(line_terminator_size + line_buffer_size + str::ASCII_CHAR);

			mem::copy(this->complete_buffer, line_buffer, line_buffer_size);
			mem::copy(&this->complete_buffer[line_buffer_size], line_terminator, line_terminator_size);

			this->complete_buffer_size = str::lenA(this->complete_buffer);

			*buffer = this->complete_buffer;
			*buffer_size = this->complete_buffer_size;

			return;
		}
	};

	// Split PLINEs into vectors 
	std::vector<line *> *vectored_lines;

public:
	// Ctors & Dtors /////////////////////////////////////////////////////////////

	// v2.0 C++ vectored PLINE constructor (1.9)
	enum {
		TYPE_TEST,
		TYPE_INIT_PLINE_ARRAY
	};
	str_string(__in const str_string& buffer, __out std::vector<line *> *line_array) :
		temporary_line(NULL),
		temporary_linew(NULL),
		raw_size(0),
		raw_buffer(NULL),
		convert(false), is_ascii(false), is_unicode(false),
		first_line(NULL),
		current_line(NULL),
		get_line_buffers_line(NULL),
		first_lineW(NULL),
		current_lineW(NULL),
		get_line_buffers_lineW(NULL),
		lpstr(NULL), lpwstr(NULL),
		lpstr_len(buffer.lenA()),
		vectored_lines(new std::vector<line *>())
	{
		//ASSERT(buffer != NULL && line_array != NULL, "str_string:: Invalid initialization parameters\n");


	}

	str_string(const LPSTR target_stringA);
	str_string(LPWSTR target_stringW);
	str_string(VOID) :
		temporary_line(NULL),
		temporary_linew(NULL),
		raw_size(0),
		raw_buffer(NULL),
		convert(false), is_ascii(false), is_unicode(false),
		first_line(NULL),
		current_line(NULL),
		get_line_buffers_line(NULL),
		first_lineW(NULL),
		current_lineW(NULL),
		get_line_buffers_lineW(NULL),
		lpstr(NULL), lpwstr(NULL),
		lpstr_len(0),
		vectored_lines(NULL)
		{
			mem::zeromem(&this->line_terminator, sizeof(term_store));		
			mem::zeromem(&this->raw_type_buffers, sizeof(this->raw_type_buffers));
		}
	~str_string();
	VOID zero_init(VOID); // Zeros all local vars

	// Constructor for loading in a sequence, splitting into lines, removing line terminator
	typedef DWORD	STR_MODE;
	enum {
		MODE_SPLIT_LINE,
		MODE_SPILT_VECTOR
	};
	str_string(STR_MODE mode, LPCSTR buffer, UINT buffer_size);

	// Constructor for inputting a integer constant. Creates a string for it.
	str_string(UINT number) :
		temporary_line(NULL),
		temporary_linew(NULL),
		raw_size(0),
		raw_buffer(NULL),
		convert(false),
		first_line(NULL),
		current_line(NULL),
		get_line_buffers_line(NULL),
		first_lineW(NULL),
		current_lineW(NULL),
		get_line_buffers_lineW(NULL),
		lpstr(NULL), lpwstr(NULL),
		lpstr_len(0),
		vectored_lines(NULL)
		{
			mem::zeromem(&this->line_terminator, sizeof(term_store));		
			mem::zeromem(&this->raw_type_buffers, sizeof(this->raw_type_buffers));
			this->lpstr = int_to_stringA(number);
		}
//private:
	//str::STR_ERROR  seq_const_state;
public:

	// Used to perform temporary operations
	PLINE			temporary_line;
	PLINEW			temporary_linew;

	// Iniitializes everything. If perform_conversion is true, then unicode <-> ascii, otherwise not.
	str::STR_ERROR	init_string(LPCSTR buffer, LPCWSTR bufferW, UINT size, UINT sizeW, bool perform_conversion);

	// Splits buffer into lines
	str::STR_ERROR load_into_lines(LPCSTR default_terminator);

	// Finds all lines that are blank, writes pattern in it
	str::STR_ERROR blank_line_into_sequence(LPCSTR pattern);

	// Replaces a line 
	str::STR_ERROR update_line_buffer(PLINE string_line, LPCSTR new_string, UINT new_string_length);

	// Removes a sequence from all lines ascii
	str::STR_ERROR remove_sequence_from_lines(LPCSTR sequence, UINT sequence_size);

	// Removes a sequence from a line
	VOID remove_sequence_from_line(PLINE line, LPCSTR sequence, UINT sequence_size);

	// Returns the first line buffer (LPCSTR), or NULL if a first line doesn't exist
	LPSTR get_first_line_buffer(VOID);

	// Gets address of first line
	PLINE get_first_line(VOID);

	// Allows us to grab line buffers, one at a time.
	LPSTR set_next_line(VOID);
	LPSTR get_new_line_buffer(VOID);

	// Cleans up local buffers
	VOID cleanup(VOID);

	// Removes comments from LINE structures
	str::STR_ERROR remove_commentsA(LPCSTR sequence);

	// Removes an ascii line
	str::STR_ERROR remove_lineA(PLINE first_line, PLINE line);

	// Returns an LPSTR from the PLINE parameter
	LPSTR convert_lines_to_string(str::PLINE first_line, PUINT string_size, LPCSTR terminator, UINT terminator_size);

	// Returns raw_type_buffers ascii
	LPSTR get_type_buffersA(PUINT buffer_size);

	// Returns values from term store
	LPSTR str_string::get_term_store(PUINT size);

	// Removes blank lines
	str::STR_ERROR remove_blank_linesA(VOID);

	// Returns a vector array containing the split strings
	std::vector<LPSTR> *split_string_by_terminatorA(__inopt const str_string *buffer, 
		__in const LPSTR term, __in const UINT term_len) const;

	// Returns an str_string vector array
	std::vector<str_string *> *split_string_by_terminatorA_(
		__inopt const str_string *buffer, __in const LPSTR term, __in const UINT term_len) const;

	// Removes old string, adds in new string
	bool add_new_string(__in const LPSTR input_string, __in const UINT input_string_size);

	// Methods /////////////////////////////////////////////////////////////////////////////////////
	UINT lenA(VOID) const;
	LPSTR to_lpstr(VOID) const;
	VOID remove_sequenceA(__in LPCSTR sequence);
	VOID add_to_prepend(__in const LPSTR buffer)
	{
		UINT buffer_len = str::lenA(buffer);
		UINT lpstr_len = this->lenA();
		if (lpstr_len == 0) {
			// No data. Create buffer.
			this->lpstr = (LPSTR)mem::malloc(buffer_len + str::ASCII_CHAR);
			mem::copy(this->lpstr, buffer, buffer_len);
		} else {
			UINT new_buffer_size = buffer_len + lpstr_len;
			LPSTR new_buffer = (LPSTR)mem::malloc(new_buffer_size + str::ASCII_CHAR);
			mem::copy(new_buffer, buffer, buffer_len);
			mem::copy(&new_buffer[buffer_len], this->lpstr, lpstr_len);
			mem::free(this->lpstr);
			this->lpstr = new_buffer;	
			this->lpstr_len = new_buffer_size;
		}

		return;
	}

	VOID add_to_append(__in const LPSTR buffer)
	{
		UINT buffer_len = str::lenA(buffer);
		UINT lpstr_len = this->lenA();
		if (lpstr_len == 0) {
			// No data
			this->lpstr = (LPSTR)mem::malloc(buffer_len + str::ASCII_CHAR);
			mem::copy(this->lpstr, buffer, buffer_len);
		} else {
			UINT new_buffer_size = buffer_len + lpstr_len;
			LPSTR new_buffer = (LPSTR)mem::malloc(new_buffer_size + str::ASCII_CHAR);
			mem::copy(new_buffer, this->lpstr, lpstr_len);
			mem::copy(&new_buffer[lpstr_len], buffer, buffer_len);
			mem::free(this->lpstr);
			this->lpstr = new_buffer;
			this->lpstr_len = new_buffer_size;
		}

		return;
	}

	/*
	str_string *operator+(__in const str_string& o) 
	{
		this->add_to_append(o.to_lpstr());
		return this;
	}

	str_string *operator+(__in const LPSTR o) 
	{
		DebugBreak();
	}  
	*/

	str_string *operator+(__in const LPSTR o)
	{
		add_to_append(o);

		return this;
	}

	str_string *operator+(__in const str_string& o)
	{
		add_to_append(*o);

		return this;
	}

	void operator*(__in const LPSTR new_string) {


	}

	// Converts to byte vector sequence
	std::vector<BYTE> *convert_to_byte_vector(__in LPCSTR buffer);

	// Operators // comparison of only lpstr variables. both memebers have it included.
	bool str_string::operator==(str_string &other) const
	{
		LPSTR other_buffer = other.to_lpstr();

		if (str::lenA(other_buffer) != str::lenA(this->lpstr)) return false;
		if (other_buffer == NULL || this->lpstr == NULL) return false;

		if (str::compareA(this->lpstr, other_buffer, other.lenA())) {
			return false;
		}

		return true;
	}

	str_string *str_string::operator+(str_string &other) const
	{
		DebugBreak();
	}

	// Appends to the end of this->lpstr, returns this
	friend std::istream& str_string::operator<<(std::istream &stream, str_string &i)
	{
		DebugBreak();
	}

	// Prepends to the beginning of this->lpstr
	str_string *str_string::operator>>(__in LPCSTR buffer)
	{
		DebugBreak();
		UINT lpstr_len = this->lenA();
		UINT new_buffer_size = str::lenA(buffer);
		LPSTR new_buffer = (LPSTR)mem::malloc(lpstr_len + new_buffer_size);
		mem::copy(new_buffer, buffer, new_buffer_size);
		mem::copy(&new_buffer[new_buffer_size], this->lpstr, lpstr_len);
		mem::free(this->lpstr);
		this->lpstr = new_buffer;
	}

	// refernce overload		
	const LPSTR& operator*(void) const
	{
		return this->lpstr;
	}

	// Comparison operator
	bool operator==(__in const LPSTR o)
	{
		UINT o_len = str::lenA(o);
		if (o_len != this->lenA()) {
			return false;
		}

		if (!str::compareA(this->lpstr, o, o_len)) {
			return true;
		}

		return false;
	}

	bool operator==(__in const str_string& o)
	{
		UINT o_len = o.lenA();
		if (o_len != this->lenA()) {
			return false;
		}

		if (!str::compareA(this->lpstr, *o, o_len)) {
			return true;
		}

		return false;
	}

	// Deals with adding lines, returning total buffer
	VOID add_line(__in LPCSTR buffer, __in LPCSTR terminator);
	VOID add_line_(__in str_string *current_line, __in str_string *terminator);

	// Returns a buffer with all vectored lines concatenated
	str_string *to_lpstr_lines_(VOID);

private:
	// Converts a LINE to a LINEW
	PLINEW convert_line_to_lineW(str::PLINE line);

	// Raw buffer
	UINT			raw_size;
	LPVOID			raw_buffer;

	// Unparsed ASCII/UNICODE buffers
	type_buffers	raw_type_buffers;

	// Switches
	bool			is_ascii;
	bool			is_unicode;
	bool			convert;

	// Strings, as loaded by constructor
	UINT			lpstr_len;
	LPSTR			lpstr;
	LPWSTR			lpwstr;

	// The line counters
	PLINE			first_line, current_line;
	PLINE			get_line_buffers_line;

	PLINEW			first_lineW, current_lineW;
	PLINEW			get_line_buffers_lineW;

	// Sequence of bytes. Can be Lines, or entire buffer. LPCSTR as input
	std::vector<BYTE> *sequence;
};
#endif


