#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>
#include <UrlMon.h>

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "download: Linking with URLMon.lib (32)")
#else 
#pragma message (OUTPUT_PRIMARY "download: Linking with URLMon.lib (32)")
#endif
#endif

#pragma comment(lib, "Urlmon.lib")

#include "common/fs.h"
#include "common/mem.h"
#include "common/str.h"
#include "net/socket.h"
#include "core/pe.h"
#include "crypt/crypt.h"
#include "http/url.h"
#include "api.h"

#define DEFAULT_BUFFER_SIZE		0x4000

// eXchange Transfer Protocol (XTP) Config
#define XTP_ENABLE
#ifdef XTP_ENABLE
#define XTP_MODE_CLIENT // Client or server mode (prevent disclosure of server objects)
#define XTP_MODE_BOTH
#define XTP_ENCRYPTION
#define XTP_MAX_SERVICE_THREADS			1024
#define XTP_SERVICE_PORT				7778
#define XTP_MAX_URL_LENGTH				2048
#define XTP_WAIT_SECONDS				CONFIG_XTP_TIMEOUT

#define XTP_LINE_TERM					"," // Splits the lines a|b,c|d
#define XTP_ELEMENT_TERM				"|" 

#ifndef DISABLE_LIBRARY_INFO
#pragma message (OUTPUT_PRIMARY "Compiling with XTP")
#endif
#endif

namespace download {
	
	static const UINT			invalid_handle		= 0;
	static const UINT			default_buffer_size	= DEFAULT_BUFFER_SIZE;

	class http 
	{
	private:
		HINTERNET				session_handle;
		HINTERNET				url_handle;

		Ptr<url_library::url>	RawURL;

		Ptr<mem::buffer2>		RawData;

		bool					download_ok;

	public:
		http(__in url_library::url& raw_url) :
			RawURL(new url_library::url(raw_url.get_raw_url())),
			session_handle(invalid_handle), url_handle(invalid_handle),
			RawData(NULL),
			download_ok(false)
		{
			this->session_handle = cInternetOpenA(	NULL, 
													INTERNET_OPEN_TYPE_DIRECT,
													NULL,
													NULL,
													0);
			if (this->session_handle == invalid_handle) {
				return;
			}
			
			this->url_handle = cInternetOpenUrlA(	this->session_handle,
													RawURL->get_raw_url(),
													NULL,
													0,
													0,
													0);
			if (this->url_handle == invalid_handle) {
				return;
			}

			UINT content_length_size = 0;
			BOOL query_status = cHttpQueryInfoA(	this->url_handle,
													HTTP_QUERY_CONTENT_LENGTH,
													NULL,
													(LPDWORD)&content_length_size,
													NULL);
			if (content_length_size == 0) {
				return;
			}

			PCHAR content_length = (PCHAR)mem::malloc(content_length_size + str::ASCII_CHAR);
			query_status = cHttpQueryInfoA(			this->url_handle,
													HTTP_QUERY_CONTENT_LENGTH,
													(LPVOID)content_length,
													(LPDWORD)&content_length_size,
													NULL);
			if (!query_status) {
				return;
			}

			UINT length = str::string_to_intA(content_length);

			// Download loop
			while (true) {
				PBYTE buffer[default_buffer_size];
				UINT bytes_read = 0;
				mem::zeromem(buffer, default_buffer_size);

				BOOL fetch_status = cInternetReadFile(	this->url_handle,
														buffer,
														default_buffer_size,
														(LPDWORD)&bytes_read);
				if (fetch_status == FALSE) {
					return;
				}

				if (RawData.get_value() == NULL) {
					RawData = new mem::buffer2((LPVOID)buffer, bytes_read);
				} else {
					RawData->append((LPVOID)buffer, bytes_read);
				}
							
				length = length - bytes_read;

				if (length == 0) {
					break;
				}

				cSleep(10);
			}

			this->download_ok = true;
		}

		~http(VOID)
		{
			if (this->url_handle != invalid_handle) {
				cInternetCloseHandle(this->url_handle);
				this->url_handle = invalid_handle;
			}

			if (this->session_handle != invalid_handle) {
				cInternetCloseHandle(session_handle);
				this->session_handle = invalid_handle;
			}
		}

		mem::buffer2 *get_raw_buffer(VOID) const
		{
			return this->RawData.get_value();
		}

		bool get_is_ok(VOID) const
		{
			return this->download_ok;
		}

		bool write_to_disk(__in str_string& file_name) const
		{
			if (this->RawData == NULL || this->RawData->get_raw_size() == 0) {
				return false;
			}

			return fs::write_raw_to_disk_(file_name, *this->RawData);
		}
	};

#ifdef XTP_ENABLE
	// XTP (eXchange Transfer Protocol)
	// XTP takes URLs in the form of xtp://address_of_server/file_name/file_name
	class xtp;
	static const DWORD _sig_size				= sizeof(DWORD);
	static const CHAR _sig_xtp[]				= { 'X', 'T', 'P', '0' };
	static const CHAR _sig_xtp_response_ok[]	= { 'O', 'K', '0', '0' };
	static const CHAR _sig_xtp_response_dne[]	= { 'D', 'N', 'E', '0' };
	static const CHAR _sig_xtp_response_fail[]  = { 'F', 'A', 'I', 'L' };
	static const CHAR _sig_xtp_request[]		= { 'R', 'E', 'Q', '0' };
	static const UINT xtp_max_service_threads	= XTP_MAX_SERVICE_THREADS;
	static const UINT xtp_service_port			= XTP_SERVICE_PORT;
	static const UINT xtp_max_url_length		= XTP_MAX_URL_LENGTH;
	static const types::TIME32 xtp_wait_seconds	= XTP_WAIT_SECONDS;

	static const UINT xtp_file_name				= 0;
	static const UINT xtp_file_path				= 1;

	static const BYTE xtp_response_ready		= 0x41;
	static const BYTE xtp_response_ready2		= 0x42;

	static const LPSTR xtp_protocol_uri			= "xtp://";

	static const LPSTR xtp_line_term			= XTP_LINE_TERM;
	static const LPSTR xtp_element_term			= XTP_ELEMENT_TERM;

	class xtp {
	protected: Ptr<socket_tools::socket_data> CurrentConnection;

	protected:
		struct request {
			CHAR signature[sizeof(_sig_xtp)];
			CHAR type[sizeof(_sig_xtp)];
			UINT response_size;
			CHAR url[xtp_max_url_length];

			request(void) {
				mem::zeromem(signature, sizeof(signature));
				mem::zeromem(type, sizeof(type));
				mem::zeromem(url, sizeof(url));
				response_size = 0;
			}
		};

	public:
		 virtual ~xtp(void)
		 {

		 }

		 virtual bool process(void) = 0;

		 // Returns a pointer to the file name
		 static str_string *isolate_request_file(__in const CHAR url[xtp_max_url_length]);
	};

	// Client
//#ifdef XTP_MODE_CLIENT
	class xtp_client : public xtp {
		Buffer2					ReturnData;

		StrString				Hostname;
		StrString				Filename;

		Ptr<url_library::url>	RequestURL;

		bool					download_ok;

	public:
		xtp_client::xtp_client(__in const url_library::url& request_url);

		virtual ~xtp_client(void)
		{

		}

		// Process for the client is to attempt a download
		virtual bool process(void);

		// Returns the raw data
		mem::buffer2 *get_raw_data(void) const
		{
			if (this->download_ok == false || ReturnData.get_is_null()) {
				return NULL;
			}

			return this->ReturnData.get_value();
		}

		bool get_is_download_ok(void) const
		{
			return this->download_ok;
		}
	};

	// Server
//#elif defined(XTP_MODE_BOTH)
	class xtp_server : public xtp {
		HANDLE dispatched_handlers[XTP_MAX_SERVICE_THREADS];
		HANDLE listener;

		WORD service_port;

		//SOCKET bind_socket;

	public: typedef struct xtp_server_input {
				StrString		RequestName;
				Ptr<pe::raw_pe>	RawPE;

				xtp_server_input(void)
				{
					RequestName = NULL;
					RawPE = NULL;
				}
			} XTP_SERVER_INPUT, *PXTP_SERVER_INPUT;

	Ptr<std::vector<xtp_server_input *>> ObjectHostInfo;

	public:
		xtp_server::xtp_server(__in const std::vector<xtp_server_input *>& object_host_info);

		virtual ~xtp_server(void)
		{
			
		}

		// Process for the server is to create a listener thread
		virtual bool process(void);

	private:
		// Listener thread
		static types::NO_RETURN_VALUE __declspec(noreturn)
			xtp_server::listener_thread(__in const std::vector<xtp_server_input *> *object_host_info);

		// Dispatch thread
		struct handler_thread_parameters {
			socket_tools::socket_data *current_connection;
			const std::vector<xtp_server_input *> *object_host_info;
			struct sockaddr_in connection_data;
			HANDLE tid;
		};
		static types::NO_RETURN_VALUE __declspec(noreturn)
			xtp_server::handler_thread(__in handler_thread_parameters *params);

		// Finds the appropriate raw data to send based on url. The dispatchers call this to find 
		// out what data to send to the client
		static PCRITICAL_SECTION sync_raw_data;
		static mem::buffer2 *get_raw_data(__in const std::vector<xtp_server_input *> *object_host_info,
										  __in const str_string& file_name);

													
	public: 
		WORD get_service_port(void) const
		{
			return this->service_port;
		}
	};

	std::vector<xtp_server::xtp_server_input *> *generate_list_from_file(__in const str_string& file_path);
//#endif
#endif
}