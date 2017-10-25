#include "httptools.h"

#include "common/mem.h"
#include "common/str.h"

#include "debug/debug.h"

using namespace http_tools;

http_tools::HTOOLS_ERROR http_request_response::set_buffer(LPCSTR buffer)
{

	if (buffer == NULL) {
		return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}

	this->full_buffer_size	= str::lenA(buffer);
	this->full_buffer		= (LPSTR)mem::malloc(this->full_buffer_size + str::ASCII_CHAR);
	if (this->full_buffer == NULL) {
		return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}
	mem::copy(this->full_buffer, buffer, this->full_buffer_size);

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::set_buffer_(__in mem::buffer2 *buffer)
{
	if (buffer = NULL) {
		return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}

	this->full_buffer_size	= buffer->get_raw_size();
	this->full_buffer		= (LPSTR)mem::malloc(this->full_buffer_size + str::ASCII_CHAR);
	mem::copy(this->full_buffer, buffer->get_raw_buffer(), this->full_buffer_size);

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::set_bufferW(LPCWSTR buffer, UINT size)
{
	if (buffer == NULL || size == 0 || *buffer == 0) {
		return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}

	this->full_buffer_sizeW	= size;
	this->full_bufferW		= (LPWSTR)mem::malloc(this->full_buffer_sizeW + str::UNICODE_TERM);
	if (this->full_bufferW == NULL) {
		return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}
	mem::copy(this->full_bufferW, buffer, this->full_buffer_sizeW);

	this->is_unicode = true;

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::pr_entry_point(LPCVOID buffer, UINT size)
{

	if (buffer == NULL || size == 0) return http_tools::HTOOLS_ER_PR_ENTRY_POINT_PARSER;

	// Construct the raw buffer from the input
	if (this->buffer != NULL) return http_tools::HTOOLS_ER_PR_ENTRY_POINT_PARSER;
	this->buffer = (str_string *)mem::malloc(sizeof(str_string));
	this->buffer->init_string(NULL, (LPCWSTR)buffer, 0, size, true);
	this->buffer->load_into_lines(str::carriage_return);
	this->buffer->remove_sequence_from_lines(str::carriage_return, str::lenA(str::carriage_return));

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::construct_string_buffer(VOID)
{

	//mem::zeromem(&this->buffer, sizeof(str_string));

	/*
	str_string string;
	mem::zeromem(&string, sizeof(string));
	string.init_string((LPCSTR)buffer, buffer_size);
	string.load_into_lines("\r\n");
	string.remove_sequence_from_lines("\r\n", str::lenA("\r\n"));
	*/
	
	if (this->buffer != NULL) return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	str_string *buffer = (str_string *)mem::malloc(sizeof(str_string));
	this->buffer = buffer;
	if (get_is_unicode() == false) {

		if (this->full_buffer == NULL || this->full_buffer_size == 0) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		str::STR_ERROR status = buffer->init_string(this->full_buffer, NULL, this->full_buffer_size, 0, true);
		if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		status = buffer->load_into_lines(str::carriage_return);
		if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		status = buffer->remove_sequence_from_lines(str::carriage_return, str::lenA(str::carriage_return));
		if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	} 
	
	if (get_is_unicode() == true) {

		if (this->full_bufferW == NULL || this->full_buffer_sizeW == 0) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		str::STR_ERROR status = buffer->init_string(NULL, this->full_bufferW, 0, this->full_buffer_sizeW, true);
		if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		status = buffer->load_into_lines(str::carriage_return);
		if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;

		//status = buffer->remove_sequence_from_lines(str::carriage_return, str::lenA(str::carriage_return));
		//if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	}

	//this->buffer = buffer;

	return http_tools::HTOOLS_ER_OK;
}

bool http_request_response::get_is_unicode(VOID)
{
	return this->is_unicode;
}

http_tools::HTOOLS_ERROR http_request_response::parse(VOID)
{
	// Get version info
	LPSTR first_line_string = this->buffer->get_first_line_buffer();
	if (first_line_string == NULL) return http_tools::HTOOLS_ER_GENERAL_FAILURE;
	if (!str::compareA(first_line_string, "HTTP/1.1", str::lenA("HTTP/1.1")) ||
		!str::compareA(first_line_string, "HTTP/1.0", str::lenA("HTTP/1.0"))) {

		this->type = http_tools::TYPE_RESPONSE;
		this->is_header			= true;
		this->is_body			= true;
		this->is_other_header	= false;

		// Version OK, Response
		PVERSION version = get_header_version();
		version->size = str::lenA("HTTP/1.x");
		version->string = (LPSTR)mem::malloc(this->http_version->size + 1);
		mem::copy(version->string, first_line_string, version->size);

		// Check if there was an error (200 OK)
		http_tools::HTOOLS_ERROR status = http_request_response::is_200_ok();
		if (status != http_tools::HTOOLS_ER_OK) {

			// Check if this is another header
			this->type				= http_tools::TYPE_OTHER_HEADER;
			this->is_body			= true;
			this->is_other_header	= true;

			http_tools::HTOOLS_ERROR header_status = parse_other_header(&this->other_header_type);
			if (header_status == http_tools::HTOOLS_ER_UNSUPPORTED_RESPONSE_HEADER) {
#ifdef DEBUG_OUT
				DBGOUT("[!] Unsupported HTTP response header");
#endif
				DebugBreak();
			}
		} else {

			// Get the transfer type (html, php, etc)
			status = get_http_type();
			HTOOLS_CHECK_ERR_RETURN(status);

			// Get the content length
			status = set_content_length(NULL);
			HTOOLS_CHECK_ERR_RETURN(status);

			// Get the connection type
			status = set_connection();
			//HTOOLS_CHECK_ERR_RETURN(status);
		}

	} else if (!str::compareA(first_line_string, "POST", str::lenA("POST"))) {

		this->type = http_tools::TYPE_POST_REQUEST;
		this->is_header			= true;
		this->is_other_header	= false;

		// POST Version
		http_tools::HTOOLS_ERROR status = get_post_version();
		HTOOLS_CHECK_ERR_RETURN(status);

		// Get the requested file
		status = set_post_file();
		HTOOLS_CHECK_ERR_RETURN(status);

		// Get the host
		status = set_request_host();
		HTOOLS_CHECK_ERR_RETURN(status);

	} else if (!str::compareA(first_line_string, "GET", str::lenA("GET"))) {

		this->type = http_tools::TYPE_GET_REQUEST;
		this->is_header			= true;
		this->is_other_header	= false;

		// Get Version
		http_tools::HTOOLS_ERROR status = get_post_version();
		HTOOLS_CHECK_ERR_RETURN(status);

		// Get the requested file
		status = set_post_file();
		HTOOLS_CHECK_ERR_RETURN(status);

		// Get the host
		status = set_request_host();
		HTOOLS_CHECK_ERR_RETURN(status);

		// Get the connection type
		status = set_connection();
		//HTOOLS_CHECK_ERR_RETURN(status);

	} else {
		DebugBreak();
	}

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::parse_other_header(
	__inout http_tools::http_request_response::PHTTP_RESPONSE_HEADER_TYPE type)
{
	if (!str::compareA(http_tools::response_header_301, 
		this->full_buffer, str::lenA(http_tools::response_header_301))) {

		// 301 header
		this->other_header_type = HTTP_RESPONSE_HEADER_TYPE_301;

#ifdef DEBUG_OUT
		DBGOUT("[+] Header response type: \"Not Modified\"\n");
#endif
	} else if (!str::compareA(http_tools::response_header_304, 
		this->full_buffer, str::lenA(http_tools::response_header_304))) {

		// 304 header
		this->other_header_type = HTTP_RESPONSE_HEADER_TYPE_304;

#ifdef DEBUG_OUT
		DBGOUT("[+] Header response type: \"Moved Permanently\"\n");
#endif
	} else if (!str::compareA(http_tools::response_header_200,
		this->full_buffer, str::lenA(http_tools::response_header_200))) {

		// 304 header
		this->other_header_type = HTTP_RESPONSE_HEADER_TYPE_200;

#ifdef DEBUG_OUT
		DBGOUT("[+] Header response type: \"200 OK\"\n");
#endif
	} else {
		return http_tools::HTOOLS_ER_UNSUPPORTED_RESPONSE_HEADER;
	}


	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::set_connection(VOID)
{
	this->connection = (PCONNECTION)mem::malloc(sizeof(CONNECTION));
	LPSTR value = find_field("Connection", str::lenA("Connection"));
	if (value == NULL || *value == '\0') return http_tools::HTOOLS_ER_SET_HOST;

	this->connection->size			= str::lenA(value);
	this->connection->string		= (LPSTR)mem::malloc(this->connection->size + 1);
	mem::copy(this->connection->string, value, this->connection->size);

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::set_request_host(VOID)
{
	if (this->host != NULL) return http_tools::HTOOLS_ER_SET_HOST;

	this->host = (PHOST)mem::malloc(sizeof(HOST));
	LPSTR value = find_field("Host", str::lenA("Host"));
	if (value == NULL || *value == '\0') return http_tools::HTOOLS_ER_SET_HOST;

	this->host->size		= str::lenA(value);
	this->host->string		= (LPSTR)mem::malloc(this->host->size + 1);
	mem::copy(this->host->string, value, this->host->size);

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::get_post_version(VOID)
{
	if (this->http_version != NULL) return http_tools::HTOOLS_ER_GET_POST_VERSION;
	PCHAR ptr = (PCHAR)this->buffer->get_first_line()->line_buffer;
	str::STR_ERROR status = str::find_sequence_pointerA(ptr, this->buffer->get_first_line()->line_size, " ", 1, &ptr);
	if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GET_POST_VERSION;

	// Should be at the version indicator now
	str::find_sequence_pointerA(ptr, this->buffer->get_first_line()->line_size, "HTTP", str::lenA("HTTP"), &ptr);
	if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GET_POST_VERSION;

	if (ptr == NULL || *ptr == '\0' || str::compareA(ptr, "HTTP", str::lenA("HTTP"))) {
		return http_tools::HTOOLS_ER_GET_POST_VERSION;
	}

	this->http_version = (PVERSION)mem::malloc(sizeof(VERSION));
	this->http_version->string = (LPSTR)mem::malloc(str::lenA(ptr) + 1);
	this->http_version->size   = str::lenA(ptr);
	mem::copy(this->http_version->string, ptr, this->http_version->size);

	return http_tools::HTOOLS_ER_OK;
}

bool http_request_response::get_is_header()
{
	return this->is_header;
}

LPSTR http_request_response::get_host_stringA(PUINT size)
{
	LPSTR host_string = this->host->string;
	if (host_string == NULL) return host_string;

	*size = this->host->size;
	return host_string;
}

LPSTR http_request_response::get_page_request(PUINT size)
{
	if (this->page_request->string == NULL || this->page_request->size == 0) return NULL;

	*size = this->page_request->size;

	return this->page_request->string;
}

http_tools::HTOOLS_ERROR http_request_response::set_post_file(VOID)
{
	if (this->page_request != NULL) return http_tools::HTOOLS_ER_GET_POST_FILE;
	PCHAR ptr = (PCHAR)this->buffer->get_first_line()->line_buffer;
	if (ptr == NULL) return http_tools::HTOOLS_ER_GET_POST_FILE;
	str::STR_ERROR status = str::find_sequence_pointerA(ptr, this->buffer->get_first_line()->line_size,
		" ", 1, &ptr);
	if (status != str::ER_STR_OK) return http_tools::HTOOLS_ER_GET_POST_FILE;

	// Determine length of the file
	PCHAR ptr2 = NULL;
	status = str::find_sequence_pointerA((LPCSTR)&ptr[1], str::lenA((LPCSTR)&ptr[1]), " ", 1, &ptr2);
	if (ptr == NULL) return http_tools::HTOOLS_ER_GET_POST_FILE;

	this->page_request			= (PPAGE_REQUEST)mem::malloc(sizeof(PAGE_REQUEST));
	this->page_request->size	= (UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr - 1);
	this->page_request->string	= (LPSTR)mem::malloc(this->page_request->size + 1);
	mem::copy(this->page_request->string, (LPCSTR)&ptr[1], this->page_request->size);

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::set_content_length(__out LPUINT length)
{
	LPSTR value = find_field("Content-Length", str::lenA("Content-Length"));
	if (value == NULL) return http_tools::HTOOLS_ER_GET_FIELD;

	if (length == NULL) {
		this->http_content_length = str::string_to_intA(value);
	} else {
		*length = str::string_to_intA(value);
		this->http_content_length = *length;
	}

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::get_http_type(VOID)
{
	str_string *buffer = this->buffer;

	LPSTR value = find_field("Content-Type", str::lenA("Content-Type"));
	if (value == NULL) return http_tools::HTOOLS_ER_GET_FIELD;

	if (this->http_type != NULL) return http_tools::HTOOLS_ER_GET_FIELD;
	this->http_type = (PTYPE)mem::malloc(sizeof(TYPE));
	this->http_type->type = (LPSTR)mem::malloc(str::lenA(value) + str::ASCII_CHAR);
	this->http_type->type_size = str::lenA(value);
	mem::copy(this->http_type->type, value, this->http_type->type_size);

	return http_tools::HTOOLS_ER_OK;
}

LPSTR http_request_response::find_field(LPCSTR field, UINT field_size)
{
	// Go through all lines
	LPSTR current_line = this->buffer->set_next_line();
	while (current_line != NULL) {

		if (!str::compareA(field, current_line, field_size)) {
			PBYTE ptr = (PBYTE)&current_line[field_size + 2]; // ": "
			if (ptr != NULL) {
				return (LPSTR)ptr;
			}
		}

		current_line = this->buffer->get_new_line_buffer();
	}

	return NULL;
}

http_tools::HTOOLS_ERROR http_request_response::is_200_ok(VOID)
{
	PCHAR ptr;
	str::STR_ERROR status = str::find_sequence_pointerA(this->buffer->get_first_line_buffer(), 
		str::lenA(this->buffer->get_first_line_buffer()), "200 OK", str::lenA("200 OK"), (LPSTR *)&ptr);
	if (status == str::ER_STR_SPLIT_LINES || ptr == NULL) return http_tools::HTOOLS_ER_RESPONSE_CODE;

	return http_tools::HTOOLS_ER_OK;
}

http_tools::HTOOLS_ERROR http_request_response::cleanup(VOID)
{
	// Clean up buffer
	this->buffer->cleanup();
	mem::free(this->buffer);

	mem::free(this->full_buffer);
	mem::free(this->http_version);
	mem::free(this->http_type);
	mem::free(this->page_request);
	mem::free(this->host);
	mem::free(this->connection);

	return http_tools::HTOOLS_ER_OK;
}

UINT http_request_response::get_raw_buffer_size(VOID)
{
	return this->full_buffer_size;
}

UINT http_request_response::get_raw_buffer_sizeW(VOID)
{
	return this->full_buffer_sizeW;
}

LPSTR http_request_response::get_raw_buffer(VOID)
{
	return this->full_buffer;
}

LPWSTR http_request_response::get_raw_bufferW(VOID)
{
	return this->full_bufferW;
}

str_string *http_request_response::get_raw_string(VOID)
{
	return (str_string *)this->buffer;
}

http_request_response::VERSION *http_request_response::get_header_version(VOID)
{
	if (this->http_version == NULL) {
		this->http_version = (PVERSION)mem::malloc(sizeof(VERSION));
	}

	return this->http_version;
}

http_tools::CONNECTION_TYPE http_request_response::get_type(VOID)
{
	return this->type;
}

bool http_request_response::is_text_body(VOID)
{
	if (this->type != http_tools::TYPE_RESPONSE) return false;

	if (this->http_type == NULL || this->http_type->type == NULL || this->http_type->type_size == 0) return false;

	LPSTR type = (LPSTR)mem::malloc(this->http_type->type_size + str::ASCII_CHAR);
	mem::copy(type, this->http_type->type, this->http_type->type_size);

	if (str::compareA(type, "text/html", str::lenA("text/html"))) {
		mem::free(type);
		return false;
	}

	mem::free(type);
	return true;
}

str::LINE *http_request_response::get_buffer_first_line(VOID)
{
	if (this->buffer == NULL) return NULL;

	PLINE line = this->buffer->get_first_line();
	if (line == NULL) return NULL;

	return line;
}

http_tools::HTOOLS_ERROR http_request_response::get_content_length(__out PUINT length)
{
	*length = 0;

	if (this->type != http_tools::TYPE_GET_REQUEST && this->type != http_tools::TYPE_RESPONSE) {
		return http_tools::HTOOLS_ER_CONTENT_LEN_ZERO;
	}

	if (length == NULL) {
		UINT content_length = 0;
		return this->set_content_length(&content_length);
	} else {
		return this->set_content_length(length);		
	}
}

bool http_request_response::get_is_body(VOID)
{
	return this->is_body;
}

// Checks whether buffer_size matches the \r\n\r\n sequence.
// Checks if all data is ascii
bool http_tools::is_data_valid_header(__in const LPCSTR buffer, __in const UINT buffer_size)
{
	if (str::is_charA(buffer, buffer_size) == false) {
		return false;
	}

	// Check if the last 4 bytes are \r\n\r\n
	if (*(PDWORD)&buffer[buffer_size - sizeof(DWORD)] != '\r\n\r\n') {
		return false;
	}

	return true;
}

http_tools::http_request_response::HEADER_TYPE 
	http_tools::http_request_response::get_header_type(types::DEFAULT_NO_PARAMETERS) const
{
	if (!str::compareA(http_tools::request_type_get, this->full_buffer, str::lenA(http_tools::request_type_get)))
	{
		return HEADER_TYPE_REQUEST_GET;
	} else if (
		!str::compareA(http_tools::request_type_post, this->full_buffer, str::lenA(http_tools::request_type_post))) 
	{
		return HEADER_TYPE_REQUEST_POST;
	} else {
		return HEADER_TYPE_RESPONSE;
	}
}

bool http_tools::http_request_response::get_is_text(types::DEFAULT_NO_PARAMETERS) const
{
	if (this->http_type == NULL || 
		this->http_type->type == NULL || 
		this->http_type->type_size == 0) 
	{
		return false;
	}

	LPSTR ptr;
	if (str::find_sequence_pointerA(this->http_type->type, this->http_type->type_size,
		http_tools::app_type_text, str::lenA(http_tools::app_type_text), &ptr) == str::ER_STR_OK) 
	{
		return true;
	}

	return false;
}