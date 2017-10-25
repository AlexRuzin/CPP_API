#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "httptools: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "httptools: Compiling 32-bit.")
#endif

#undef LIBRARY_HTTP_TOOLS
#define LIBRARY_HTTP_TOOLS

#include "common/str.h"
#ifndef LIBRARY_NET_SOCKET
#include "net/socket.h"
#endif

// Header related constants
#define HTTP_RESPONSE_200_OK	"HTTP/1.1 200 OK"
#define HTTP_STANDARD_TERM		"\r\n"

#define SERVICE_PORT_HTTP		80

#define HTTP_TOOLS

namespace http_tools {

	// Not needed
	enum {
		HTOOLS_GET_HTTP_VERSION,
		HTOOLS_GET_HTTP_URI,
		HTOOLS_GET_HTTP_METHOD,
		HTOOLS_GET_DATA,
		HTOOLS_GET_HOST
	};

	// Error related stuff
	typedef UINT		HTOOLS_ERROR;
	enum {
		HTOOLS_ER_OK,
		HTOOLS_ER_GENERAL_FAILURE,
		HTOOLS_ER_PARSE,
		HTOOLS_ER_VERSION,
		HTOOLS_ER_RESPONSE_CODE,
		HTOOLS_ER_GET_FIELD,
		HTOOLS_ER_GET_POST_FILE,
		HTOOLS_ER_GET_POST_VERSION,
		HTOOLS_ER_SET_HOST,
		HTOOLS_ER_PR_ENTRY_POINT_PARSER,
		HTOOLS_ER_CONTENT_LEN_ZERO,
		HTOOLS_ER_UNSUPPORTED_RESPONSE_HEADER
	};

	enum {
		TYPE_POST_REQUEST,
		TYPE_GET_REQUEST,
		TYPE_RESPONSE,
		TYPE_BODY_DATA,
		TYPE_OTHER_HEADER
	};
#define HTOOLS_CHECK_ERR_RETURN(x) if (x != http_tools::HTOOLS_ER_OK) return x;

	typedef UINT CONNECTION_TYPE;

	// Header related constants
	static const LPSTR response_200_ok		= HTTP_RESPONSE_200_OK;
	static const LPSTR standard_terminator	= HTTP_STANDARD_TERM;

	// Other constants
	static const UINT service_port_http		= SERVICE_PORT_HTTP;
	static const LPSTR http_prefix			= "http://";

	static str_string *data_type_octet		= new str_string("application/octet-stream");

	// Implements: 301, 304
	static const LPSTR response_header_301	= "HTTP/1.1 304 Not Modified";
	static const LPSTR response_header_304	= "HTTP/1.1 301 Moved Permanently";
	static const LPSTR response_header_200  = "HTTP/1.1 200";

	// POST/GET strings
	static const LPSTR request_type_get		= "GET";
	static const LPSTR request_type_post	= "POST";

	// Application type
	static const LPSTR app_type_text		= "text/html";

	// Checks if data is in fact a header
	bool is_data_valid_header(__in const LPCSTR buffer, __in const UINT buffer_size);

	class http_request_response;
	typedef Ptr<http_request_response> HttpHeader;

	class http_request_response {

		typedef struct {
			LPSTR	string;
			UINT	size;
		} VERSION, *PVERSION;

		typedef struct {
			LPSTR	type;
			UINT	type_size;
		} TYPE, *PTYPE;

		///test/demo_form.asp
		typedef struct {
			LPSTR	string;
			UINT	size;
		} PAGE_REQUEST, *PPAGE_REQUEST;

		typedef struct {
			LPSTR	string;
			UINT	size;
		} HOST, *PHOST;

		// Connection: Keep-Alive/close, etc
		typedef struct {
			LPSTR	string;
			UINT	size;
		} CONNECTION, *PCONNECTION;

		// Application type. Used when generating a response header
		str_string *content_type;
		str_string *content_length;

		// Buffer
		socket_tools::data *raw_buffer;
	#define HTTP_CHECK_DELETE(x) if (x != NULL) delete x
	#define HTTP_CHECK_UNMALLOC(x) if (x != NULL) mem::free(x)

		str_string	*full_get_response_buffer;

		bool is_ok;

	public: 
		// Constructors
		http_request_response(VOID) :
			raw_buffer(NULL),
			full_get_response_buffer(NULL),
			full_buffer(NULL),
			full_bufferW(NULL),
			full_buffer_size(0), full_buffer_sizeW(0),
			buffer(NULL),
			is_header(false), is_body(false),
			http_version(NULL), http_type(NULL), page_request(NULL),
			host(NULL), connection(NULL), http_content_length(0), type(NULL),
			is_unicode(false),
			host_string(NULL),
			version_string(NULL),
			connection_type_string(NULL),
			page_request_string(NULL),
			content_type(NULL),
			content_length(0),
			is_ok(false), other_header_type(0xffffffff),
			Url(NULL)
			{

			}

		http_request_response(__in_free socket_tools::data *input_buffer) :
			raw_buffer(input_buffer), full_get_response_buffer(NULL),
			full_buffer(NULL),
			full_bufferW(NULL),
			full_buffer_size(0), full_buffer_sizeW(0),
			buffer(NULL),
			is_header(false), is_body(false),
			http_version(NULL), http_type(NULL), page_request(NULL),
			host(NULL), connection(NULL), http_content_length(0), type(NULL),
			is_unicode(false),
			host_string(NULL),
			version_string(NULL),
			connection_type_string(NULL),
			page_request_string(NULL),
			content_type(NULL),
			content_length(NULL),
			is_ok(false), other_header_type(0xffffffff),
			Url(NULL)
			{
				LPVOID buffer_raw;
				UINT buffer_size;
				input_buffer->get_buffer(&buffer_raw, &buffer_size);

				HTOOLS_ERROR parse_status	= this->set_buffer((LPCSTR)buffer_raw);
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->construct_string_buffer();
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->parse();
				if (parse_status != HTOOLS_ER_OK) return;

				this->is_ok = true;
			}

		http_request_response(__in mem::buffer2 *raw_data) :
			raw_buffer(NULL), full_get_response_buffer(NULL),
			full_buffer(NULL),
			full_bufferW(NULL),
			full_buffer_size(0), full_buffer_sizeW(0),
			buffer(NULL),
			is_header(false), is_body(false),
			http_version(NULL), http_type(NULL), page_request(NULL),
			host(NULL), connection(NULL), http_content_length(0), type(NULL),
			is_unicode(false),
			host_string(NULL),
			version_string(NULL),
			connection_type_string(NULL),
			page_request_string(NULL),
			content_type(NULL),
			content_length(NULL),
			is_ok(false), other_header_type(0xffffffff),
			Url(NULL)
			{
				LPVOID buffer_raw;
				UINT buffer_size;
				raw_data->get_raw_data(&buffer_raw, &buffer_size);

				HTOOLS_ERROR parse_status	= this->set_buffer((LPCSTR)buffer_raw);
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->construct_string_buffer();
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->parse();
				if (parse_status != HTOOLS_ER_OK) return;

				this->is_ok = true;
			}

		// Clone constructor
		http_request_response(__in http_request_response *o) :
			raw_buffer(NULL), full_get_response_buffer(NULL),
			full_buffer(NULL),
			full_bufferW(NULL),
			full_buffer_size(0), full_buffer_sizeW(0),
			buffer(NULL),
			is_header(false), is_body(false),
			http_version(NULL), http_type(NULL), page_request(NULL),
			host(NULL), connection(NULL), http_content_length(0), type(NULL),
			is_unicode(false),
			host_string(NULL),
			version_string(NULL),
			connection_type_string(NULL),
			page_request_string(NULL),
			content_type(NULL),
			content_length(NULL),
			is_ok(false), other_header_type(0xffffffff),
			Url(NULL)
			{
				LPSTR raw_header = o->get_raw_buffer();

				HTOOLS_ERROR parse_status	= this->set_buffer((LPCSTR)raw_header);
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->construct_string_buffer();
				if (parse_status != HTOOLS_ER_OK) return;
				parse_status				= this->parse();
				if (parse_status != HTOOLS_ER_OK) return;

				this->is_ok = true;
			}

		// Builds a GET response header from data type and content size
		http_request_response(__in str_string *data_type, __in UINT content_size) :
			raw_buffer(NULL),
			full_get_response_buffer(NULL),
			full_buffer(NULL),
			full_bufferW(NULL),
			full_buffer_size(0), full_buffer_sizeW(0),
			buffer(NULL),
			is_header(false), is_body(false),
			http_version(NULL), http_type(NULL), page_request(NULL),
			host(NULL), connection(NULL), http_content_length(0), type(NULL),
			is_unicode(false),
			host_string(NULL),
			version_string(NULL),
			connection_type_string(NULL),
			page_request_string(NULL),
			content_type(data_type),
			content_length(new str_string(content_size)),
			is_ok(false), other_header_type(0xffffffff),
			Url(NULL)
			{
				content_type->add_to_prepend("Content-Type: ");
				content_length->add_to_prepend("Content-Length: ");

				str_string *line_buffer = new str_string();
				line_buffer->add_line_(new str_string(response_200_ok), new str_string(standard_terminator));
				line_buffer->add_line_(content_type, new str_string(standard_terminator));
				line_buffer->add_line_(content_length, new str_string(standard_terminator));
				line_buffer->add_line_(new str_string(standard_terminator), NULL);
			
				full_get_response_buffer = line_buffer->to_lpstr_lines_();
			}

		~http_request_response(VOID)
		{
			HTTP_CHECK_DELETE(host_string);
			HTTP_CHECK_DELETE(version_string);
			HTTP_CHECK_DELETE(connection_type_string);
			HTTP_CHECK_DELETE(page_request_string);
			//HTTP_CHECK_DELETE(buffer); //fixme!!!
			HTTP_CHECK_DELETE(raw_buffer);
			HTTP_CHECK_DELETE(content_type);
			HTTP_CHECK_DELETE(content_length);
			HTTP_CHECK_DELETE(full_get_response_buffer);

			HTTP_CHECK_UNMALLOC(full_buffer);
			HTTP_CHECK_UNMALLOC(full_bufferW);
			HTTP_CHECK_UNMALLOC(http_version);
			HTTP_CHECK_UNMALLOC(http_type);
			HTTP_CHECK_UNMALLOC(page_request);
			HTTP_CHECK_UNMALLOC(host);
			HTTP_CHECK_UNMALLOC(connection);
		}

		// Builds & returns the new GET response (obsolete)
		str_string *build_and_get_response(VOID) 
		{
			str_string *response_header = new str_string();

			return response_header;
		}

		// Main entry point from the PR hooks
		http_tools::HTOOLS_ERROR pr_entry_point(LPCVOID buffer, UINT size);
	
		// Checks for Content-Type text/html
		bool get_is_text(types::DEFAULT_NO_PARAMETERS) const;

		// Sets the raw buffer
		http_tools::HTOOLS_ERROR	set_buffer(LPCSTR buffer);
		http_tools::HTOOLS_ERROR	set_buffer_(__in mem::buffer2 *buffer);

		// Constructs the string object for the raw buffer
		http_tools::HTOOLS_ERROR construct_string_buffer(VOID);

		// Gets the raw buffer size
		UINT get_raw_buffer_size(VOID);
		UINT get_raw_buffer_sizeW(VOID);

		// Gets the raw buffer
		LPSTR get_raw_buffer(VOID);
		LPWSTR get_raw_bufferW(VOID);

		// Returns this->buffer
		str_string *get_raw_string(VOID);

		// Gets the VERSION of the request/response. Allocates version if it doesn't exist.
		VERSION *get_header_version(VOID);

		// Parses an str_string buffer into objects
		http_tools::HTOOLS_ERROR parse(VOID);

		// Releases memory
		http_tools::HTOOLS_ERROR cleanup(VOID);

		// This is the actual input function
		http_tools::HTOOLS_ERROR set_bufferW(LPCWSTR buffer, UINT size);

		// Returns the is_unicode variable
		bool get_is_unicode(VOID);

		// Returns is_header
		bool get_is_header(VOID);

		// Return is_body field
		bool get_is_body(VOID);

		bool get_is_ok(VOID) const
		{
			return this->is_ok;
		}

		// Returns PHOST->string, size
		LPSTR get_host_stringA(PUINT size);

		// Returns PAGE_REQUEST->string used by injects
		LPSTR get_page_request(PUINT size);

		// Returns the type of request
		http_tools::CONNECTION_TYPE get_type(VOID);

		// Called by webinjects to determine if the request response contains a text body
		bool is_text_body(VOID);

		// Returns the request type (GET/POST), if it exists (will fail on response header)
		enum {
			HEADER_TYPE_RESPONSE,
			HEADER_TYPE_REQUEST_GET,
			HEADER_TYPE_REQUEST_POST
		};
		typedef DWORD HEADER_TYPE;
		HEADER_TYPE get_header_type(types::DEFAULT_NO_PARAMETERS) const;

		// Returns the entire URL
	private:
		Ptr<str_string>		Url;
	public:
		str_string *get_complete_url(VOID) 
		{
			if (Url.get_value() == NULL) {
				if (this->host_string == NULL) {
					this->host_string = get_string(TYPE_HOST);
					ASSERT(this->host_string != NULL, "httptools: Invalid Header");
				}

				if (this->page_request_string == NULL) {
					this->page_request_string = get_string(TYPE_PAGE_REQUEST);
					ASSERT(this->page_request_string != NULL, "httptools: Invalid Header");
				}

				// Generate URL
				UINT prefix_size = str::lenA(http_prefix);
				LPSTR raw_url = (LPSTR)mem::malloc(prefix_size +
					this->host_string->lenA() + this->page_request_string->lenA() +
					str::ASCII_CHAR);
				mem::copy(raw_url, http_prefix, prefix_size);
				mem::copy(&raw_url[prefix_size], this->host_string->to_lpstr(),
					this->host_string->lenA());
				mem::copy(&raw_url[str::lenA(raw_url)], this->page_request_string->to_lpstr(),
					this->page_request_string->lenA());
				this->Url = new str_string(raw_url);

				mem::free(raw_url);
			}

			return Url.get_value();
		}

		// Returns the first line of the http buffer
		str::LINE *get_buffer_first_line(VOID);

		// Gets the content length of response header
		http_tools::HTOOLS_ERROR get_content_length(__outopt PUINT length);

		// Returns the get response buffer vectored elements into lpstr
		LPSTR get_get_response_buffer(VOID) const
		{
			return this->full_get_response_buffer->to_lpstr();
		}

		// Returns an str_string of a specified field. deleteing the class is sufficient to clean all this up.
		str_string		*host_string;
		str_string		*version_string;
		str_string		*connection_type_string;
		str_string		*page_request_string;
		typedef DWORD STRING_TYPE;
		enum {
			TYPE_HOST,
			TYPE_VERSION,
			TYPE_CONNECTION_TYPE,
			TYPE_PAGE_REQUEST
		};
		str_string *get_string(STRING_TYPE type) 
		{
			switch (type)
			{
			case TYPE_HOST:
				if (host != NULL) {
					if (host_string != NULL) {
						return host_string;
					}
					host_string = new str_string(host->string);
					return host_string;
				}
				return NULL;
			case TYPE_VERSION:
				if (http_version != NULL) {
					if (version_string != NULL) {
						return version_string;
					}
					version_string = new str_string(http_version->string);
					return version_string;
				}
				return NULL;
			case TYPE_CONNECTION_TYPE:
				if (connection != NULL) {
					if (connection_type_string != NULL) {
						return connection_type_string;
					}
					connection_type_string = new str_string(connection->string);
					return connection_type_string;
				}
				return NULL;
			case TYPE_PAGE_REQUEST:
				if (page_request != NULL) {
					if (page_request_string != NULL) {
						return page_request_string;
					}
					page_request_string = new str_string(page_request->string);
					return page_request_string;
				}
				return NULL;
			default:
				return NULL;
			}
		}
	private:

		// Checks if there was an error in HTTP transmission (checks for 200 OK)
		http_tools::HTOOLS_ERROR is_200_ok(VOID);

		// Parses the http method type
		http_tools::HTOOLS_ERROR get_http_type(VOID);

		// Returns a specific HTTP field, like Date, or Context, etc
		LPSTR find_field(LPCSTR field, UINT field_size);

		// Implements: 301, 304
		bool is_other_header;
	public:
		typedef DWORD HTTP_RESPONSE_HEADER_TYPE, *PHTTP_RESPONSE_HEADER_TYPE;
		bool get_is_other_header(PHTTP_RESPONSE_HEADER_TYPE type) const
		{
			*type = this->other_header_type;
			return this->is_other_header;
		}
		enum {
			HTTP_RESPONSE_HEADER_TYPE_200,
			HTTP_RESPONSE_HEADER_TYPE_301,
			HTTP_RESPONSE_HEADER_TYPE_304
		};

	private:
		HTTP_RESPONSE_HEADER_TYPE other_header_type;
		http_tools::HTOOLS_ERROR http_request_response::parse_other_header(
			__inout http_tools::http_request_response::PHTTP_RESPONSE_HEADER_TYPE type);

		// Sets the content length
		http_tools::HTOOLS_ERROR set_content_length(__out LPUINT length);

		// Creates a PPAGE_REQUEST structure storing the requested file name
		http_tools::HTOOLS_ERROR set_post_file(VOID);

		// Gets the version of the POST request
		http_tools::HTOOLS_ERROR get_post_version(VOID);

		// Sets the HOST structure (dns or ip of host)
		http_tools::HTOOLS_ERROR set_request_host(VOID);

		// Sets the connection field in GET
		http_tools::HTOOLS_ERROR set_connection(VOID);

		// Raw buffers as passed by NSPR hook
		LPSTR				full_buffer;
		LPWSTR				full_bufferW;
		UINT				full_buffer_size;
		UINT				full_buffer_sizeW;

		// String object as passed by either full_buffer or full_bufferW
		str_string			*buffer;

		bool				is_header;
		bool				is_body;

		PVERSION			http_version;
		PTYPE				http_type;
		PPAGE_REQUEST		page_request;
		PHOST				host;
		PCONNECTION			connection;
		UINT				http_content_length;
		CONNECTION_TYPE		type;

		// Settings
		bool				is_unicode;
	};		
}

