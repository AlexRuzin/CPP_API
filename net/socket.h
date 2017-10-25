#pragma once 
//#define STRICT

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "socket: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "socket: Compiling 32-bit.")
#endif
#endif

#define USE_SOCKET_ENCRYPTION //Uses the standard encryption layer on the socket_data structure
#ifndef DISABLE_SECONDARY_OUTPUT
#ifdef USE_SOCKET_ENCRYPTION
#pragma message (OUTPUT_PRIMARY "socket: Using encryption layer")
#else
#pragma message (OUTPUT_PRIMARY "socket: Encryption layer disabled")
#endif
#endif

#define DISABLE_HTTPTOOLS

#undef LIBRARY_NET_SOCKET
#define LIBRARY_NET_SOCKET

/*
//#include <stdio.h>
//#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <Schannel.h>
*/

#include "api.h"
#include "common/str.h"
#include "common/mem.h"
#include "common/id.h"
#ifndef DISABLE_HTTPTOOLS
#ifndef LIBRARY_HTTP_TOOLS
#include "http/httptools.h"
#endif
#endif

#include "external/z.h"

//#include <WinSock.h> 
//#include <Windows.h>


//#include "external/ssl.h"

// Project specific timings
#ifdef PROJECT_HTTPMIRROR
// Timings for io_thread
#define TIMEOUT_S_IO					300	// amount of time 
#define TIMEOUT_MS_IO					0
#define TIMEOUT_ITERATIONS				500 //unused

// Timings for wait_and_read thread
#define TIMEOUT_S						5
#define TIMEOUT_MS						0

// Timeout for a new socket to be initialized with the target httpd
#define TIMEOUT_WAIT					10000 // Time that it takes wait_thread to timeout

#define SOCKET_DEFAULT_HTTP				80

// send_data MTU
#define SEND_DATA_MTU					1500

// Buffer size for wait_and_read
#define RECV_BUFFER_SIZE				2048
#elif defined (PROJECT_BACKDOOR)
// Timings for io_thread
#define TIMEOUT_S_IO					300	// amount of time 
#define TIMEOUT_MS_IO					0
#define TIMEOUT_ITERATIONS				500 //unused

// Timings for wait_and_read thread
#define TIMEOUT_S						5
#define TIMEOUT_MS						0

// Timeout for a new socket to be initialized with the target httpd
#define TIMEOUT_WAIT					10000 // Time that it takes wait_thread to timeout

#else
//#error "socket.h: No project-specific timings defined"
#endif

// Timeout for retrying gethostbyname
#define TIMEOUT_GETHOSTBYNAME_RETRY		5000

// listener thread: Time until next accept
#define TIME_TO_WAIT_CREATETHREAD		10

#ifndef SERVICE_PORT_HTTP
#define SERVICE_PORT_HTTP				80
#endif

// Buffer size for wait_and_read
#define RECV_BUFFER_SIZE				0x8000
#define RECV_ITERATION_TIMEOUT			50			// Time it takes for each RECV_BUFFER_SIZE packet to be read

// Debug
#define ENABLE_WSASTARTUP				true
#define WAIT_AND_READ_NEW_ALGORITHM		// Uses the v2.0 wait_and_read algorithm

namespace socket_tools {

	// Types
#define __st_thread_conv				_cdecl
#define __st_handler_conv				_cdecl
	typedef DWORD						ST_ERROR;
	typedef VOID						SOCKET_THREAD_ENTRY;
	typedef VOID						SOCKET_HANDLER_ENTRY;
	typedef SOCKET						*PSOCKET;
	typedef WORD						S_PORT;

	// Error codes
	enum {
		ST_ER_OK,
		ST_ER_FAIL,
		ST_ER_WSA
	};

	// Timings
	/*
	static const UINT _timeout_s_io		= TIMEOUT_S_IO;
	static const UINT _timeout_ms_io	= TIMEOUT_MS_IO;
	static const UINT _timeout_s		= TIMEOUT_S;
	static const UINT _timeout_ms		= TIMEOUT_MS;
	static const UINT _timeout_wait		= TIMEOUT_WAIT;
	static const UINT _timeout_iter		= TIMEOUT_ITERATIONS;*/

	// Thread functions
	HANDLE start_thread(__in const LPTHREAD_START_ROUTINE oep, 
		__in const LPVOID parameter);

	// Constants
	static const UINT default_http_port	= SERVICE_PORT_HTTP;
	static const bool init_wsastartup	= ENABLE_WSASTARTUP;
	static const int recv_buf_size		= RECV_BUFFER_SIZE;
	static const UINT recv_iter			= RECV_ITERATION_TIMEOUT;


	// Data that is received while waiting
	class data;
	//typedef Ptr<data>		Data;

	class data {
		LPVOID	buffer;
		UINT	size;

		str_string	*file_directory;
		str_string	*file_host;

		SOCKET	src_socket;
		SOCKET  dst_socket;

		Buffer2 RawData;

	public:
		data(VOID) : buffer(NULL), size(0) {}
		data(__in const LPVOID input, __in const UINT input_size, 
			__in const SOCKET source, __inopt SOCKET destination) :
			buffer((LPVOID)mem::malloc(input_size)),
			size(input_size),
			src_socket(source),
			dst_socket(destination),
			file_directory(NULL),
			file_host(NULL), RawData(NULL)
			{
				mem::copy(this->buffer, input, input_size);
			}
		data(__in const data *o) :
			file_directory(NULL),
			file_host(NULL), RawData(NULL)
		{
			LPVOID raw_buffer;
			UINT buffer_size;
			o->get_buffer(&raw_buffer, &buffer_size);
			this->buffer = (LPVOID)mem::malloc(buffer_size);
			mem::copy(this->buffer, raw_buffer, buffer_size);

			this->size = buffer_size;
			this->src_socket = o->get_socket(socket_tools::data::TYPE_SOURCE);
			this->dst_socket = o->get_socket(socket_tools::data::TYPE_DESINATION);
		}

		data(LPVOID input, UINT input_size, str_string *host, str_string *directory) :
			buffer(input),
			size(input_size),
			file_directory(directory),
			file_host(host),
			RawData(NULL)
			{
				DebugBreak();
			}
		~data(void)
		{
			if (buffer != NULL) mem::free(buffer);
		}

		void get_buffer(__inout LPVOID *buffer, PUINT buffer_size) const
		{
			*buffer = this->buffer;
			*buffer_size = this->size;
		}

		LPVOID get_buffer2(void) const
		{
			return this->buffer;
		}

		UINT get_size(void) const
		{
			return this->size;
		}

		mem::buffer2 *get_buffer(void)
		{
			if (this->buffer == NULL || this->size == 0) {
				return NULL;
			}

			if (this->RawData == NULL) {
				this->RawData = new mem::buffer2(this->buffer, this->size);
			}

			return this->RawData.get_value();
		}

		typedef bool SOCKET_TYPE;
		enum {
			TYPE_SOURCE,
			TYPE_DESINATION
		};
		SOCKET get_socket(SOCKET_TYPE type) const
		{
			switch (type)
			{
				case TYPE_SOURCE:
					return this->src_socket;
				case TYPE_DESINATION:
					return this->dst_socket;
			}
			return false;
		}
	};

	// Structure for quick-resolving hostname
	/*
	struct {
		LPSTR		domain_name;
		
	} DNS_CACHE, *PDNS_CACHE;*/

	// Socket binding functions //////////////////////////////////////////////////
	typedef DWORD SOCKET_BIND_HANDLE;
	class socket_bind;
	static std::vector<socket_bind *> bound_sockets;

	// Definitions for callbacks used for error and data processing
	typedef SOCKET_HANDLER_ENTRY (__st_handler_conv *error_callback)
		(__in const SOCKET *a, __in const SOCKET *b, socket_bind *binding); // Called if there is a bind error
	typedef SOCKET_HANDLER_ENTRY (__st_handler_conv *data_callback)
		(__inoutopt socket_tools::data *d); // Called to filter data in the socket bind
	class socket_data;
	socket_tools::socket_bind *bind_sockets(SOCKET a, SOCKET b, 
		socket_data *sa, socket_data *sb,
		error_callback error_handler, data_callback data_handler, 
		__in const types::TIME32 io_thread_select_timeout_s,
		__in const types::TIME32 io_thread_select_timeout_ms);	

	// Wait and read function
	typedef DWORD ER_WAIT_AND_READ;
	enum {
		ER_WAIT_OK,
		ER_WAIT_FAIL,
		ER_WAIT_NOTHING_RECEIVED,
		ER_WAIT_TIMEOUT,
		ER_WAIT_SOCKET_FAILURE
	};
	socket_tools::ER_WAIT_AND_READ wait_and_read(__in SOCKET rx_socket, 
		__in const types::TIME32 time_s, 
		__in const types::TIME32 time_u, 
		__inout LPVOID *buffer,
		__out PUINT buffer_size);
	socket_tools::ER_WAIT_AND_READ wait_and_read(__in socket_data& rx_socket,
		__in const types::TIME32 time_s,
		__in const types::TIME32 time_u, 
		__inout socket_tools::data** buffer_data);

	// socket class and data
	class socket_data {
	public:
		typedef DWORD SOCKET_DATA_ERROR;

	private:
		typedef socket_data		*__this_ptr;

		// Socket data
		SOCKET					socket_handle;

		// Wait and read thread handle
		HANDLE					wait_and_read_thread;
	
		// Destination domain. Optional through socket_data(__in const init_socket_data *data)
		Ptr<str_string>			IP;
		//str_string			*domain;
		S_PORT					port;

		// Timeings
		static const UINT default_zero_time = 0;
		types::TIME32			_timing_initial_request_s;
		types::TIME32			_timing_initial_request_ms;

		// Wraps wait_and_read. Requests data.
		bool					is_data_available;
		Ptr<data>				WaitData;

		bool					is_connected;

#ifdef USE_SOCKET_ENCRYPTION
		Ptr<crypt::channel>		EncryptedChannel;
#endif

	public:
		socket_data(VOID) :
			socket_handle(INVALID_SOCKET),
			IP(NULL), port(0),
			wait_and_read_thread(INVALID_HANDLE_VALUE),
			init_data(NULL),
			WaitData(NULL),
			_timing_initial_request_s(default_zero_time), 
			_timing_initial_request_ms(default_zero_time),
#ifdef USE_SOCKET_ENCRYPTION
			EncryptedChannel(NULL),
#endif
			is_data_available(false), is_connected(false)
			{

			}
		socket_data(__in const SOCKET tx_socket) :
			socket_handle(tx_socket),
			IP(NULL), port(0),
			wait_and_read_thread(INVALID_HANDLE_VALUE),
			init_data(NULL),
			WaitData(NULL),
			_timing_initial_request_s(default_zero_time), 
			_timing_initial_request_ms(default_zero_time),
#ifdef USE_SOCKET_ENCRYPTION
			EncryptedChannel(NULL),
#endif
			is_data_available(false), is_connected(false)
			{

			} 

		enum server_type {
			TYPE_DOMAIN,
			TYPE_IP
		};

		typedef struct init_socket_data {
			union {
				str_string *ip;
				str_string *domain;
			};
			server_type		type; //true: ip. false: domain
			S_PORT			port;

			types::TIME32	gethostbyname_timeout_iterations; // Number of times gethostbyname may fail

			init_socket_data(VOID)
			{
				ip			= NULL;
				type		= TYPE_DOMAIN;
				port		= 0;
				gethostbyname_timeout_iterations = 0;
			}
		} INIT_SOCKET_DATA, *PINIT_SOCKET_DATA;
		socket_data(__in PINIT_SOCKET_DATA data);

		socket_data(__in const socket_data *o) :
			socket_handle(o->socket_handle),
			IP(NULL), port(0),
			wait_and_read_thread(INVALID_HANDLE_VALUE),
			init_data(NULL), WaitData(NULL),
			_timing_initial_request_s(default_zero_time), 
			_timing_initial_request_ms(default_zero_time),
#ifdef USE_SOCKET_ENCRYPTION
			EncryptedChannel(NULL),
#endif
			is_data_available(false), is_connected(false)
		{

		}

		~socket_data()
		{
			if (this->socket_handle != INVALID_SOCKET) {
				close_socket(&this->socket_handle);
				this->socket_handle = INVALID_SOCKET;
			}
			if (this->wait_and_read_thread != INVALID_HANDLE_VALUE) {
				cTerminateThread(this->wait_and_read_thread, 0);
			}

			if (this->init_data != NULL) {
				/*
				if (this->init_data->type == TYPE_DOMAIN) {
					delete this->init_data->domain;
				} else if (this->init_data->type == TYPE_IP) {
					delete this->init_data->ip;
				}*/

				delete this->init_data;
				this->init_data = NULL;
			}

			//if (this->WaitData.get_is_null() == false) {
			//	this->WaitData.clear();
			//}
		}

#ifdef USE_SOCKET_ENCRYPTION
		// Sets up the encrypted channel
		public: bool socket_data::setup_encryption_client(void);
		public: bool socket_data::setup_encryption_server(void); 
#endif

		SOCKET socket_data::get_socket(VOID) const
		{
			return this->socket_handle;
		}

		VOID socket_data::close_socket(__inout PSOCKET tx_socket)
		{
			if (tx_socket == NULL || *tx_socket == INVALID_SOCKET) return;
			closesocket(*tx_socket);
		}

		// Waits on data, dispatches callback
		enum {
			WAIT_OK,
			WAIT_FAIL
		};
		// Callback on function when reading data from a socket
		typedef SOCKET_THREAD_ENTRY (__st_thread_conv *f_handler)
			(__inout data *buffer, __in socket_data *data);
		socket_data::SOCKET_DATA_ERROR wait_and_dispatch(
			__in const SOCKET rx_socket, __in const f_handler handler,
			__in const types::TIME32 _timing_initial_get_request_timeout_s, 
			__in const types::TIME32 _timing_initial_get_request_timeout_ms);
		static socket_tools::SOCKET_THREAD_ENTRY __st_thread_conv 
			wait_thread(__in const __this_ptr This);

		// Wait and read wrapper. If there is existing data that hasn't been read, WAIT_ERROR_DATA_WAITING 
		// error will be returned. 
		typedef DWORD WAIT_ERROR;
		enum {
			WAIT_ERROR_DATA_AVAILABLE,
			WAIT_ERROR_NOTHING_RECEIVED,
			WAIT_ERROR_DATA_WAITING,
			WAIT_ERROR_FAILURE
		};
		WAIT_ERROR wait_for_data(__in const types::TIME32 time_s,
			__in const types::TIME32 time_ms);
		socket_tools::data *wait_for_data_get_data(__inopt LPVOID *raw_buffer,
			__inopt PUINT raw_buffer_size)
		{
			if (this->is_data_available == false) {
				return NULL;
			} 
  
			if (raw_buffer != NULL && raw_buffer_size != 0) {
				LPVOID buffer;
				UINT buffer_size;
				this->WaitData->get_buffer(&buffer, &buffer_size);
				*raw_buffer = buffer;
				*raw_buffer_size = buffer_size;
			}

			this->is_data_available = false;

			return this->WaitData.get_value();
		}

		bool send_data(__in const mem::buffer2& raw_data) const
		{
			if (this->socket_handle == INVALID_SOCKET) {
				return false;
			}

			mem::buffer2 *main_buffer = NULL;

#ifdef USE_SOCKET_ENCRYPTION
			Buffer2 EncryptedBuffer = this->EncryptedChannel->encrypt(raw_data);
			INT send_status = send(this->socket_handle, (const char *)**EncryptedBuffer,
				EncryptedBuffer->get_raw_size(), 0);
			if (send_status != EncryptedBuffer->get_raw_size()) {
				return false;
			} 

			main_buffer = EncryptedBuffer.get_value();
#else	 
			main_buffer = *raw_data;
#endif

			return true;
		}

		bool get_is_connected(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->is_connected;
		}

	private:
		// Wait handler called by wait_and_dispatch.
		f_handler		handler;

		// Init data parameter for constructor initializing a new socket
		PINIT_SOCKET_DATA init_data;
	};
	const std::vector<socket_data *> open_sockets;

	// Interface /////////////////////////////////////////////////////////////////
	// Initializes a socket (obsolete) handled by constructor
	static WSADATA *wsadata = NULL;
	/*
	socket_data *init_socket(__inout WSADATA wsadata, 
		__in const str_string *ip_address,
		__in const str_string *domain_name, 
		__in const socket_tools::S_PORT port);
	*/

	// Stream class //////////////////////////////////////////////////////////////
	class stream;
	stream *find_stream(__in const data *d);
	static CRITICAL_SECTION						*stream_sync	= NULL;
	static std::vector<stream *>				*stream_array	= NULL;

	class stream {
	private:
		// Vectored data
		std::vector<data *>						*data_array;

		// Sockets
		socket_data								*source;
		socket_data								*destination;

		// End stream size. Not all data was received, but a header indicated (as per http,
		// etc) that this much data should exist in the stream
		UINT									stream_end_size;

		// ID
		id_info::id								*stream_id;

		// Headers, optional. 0 is request, 1 is response
#ifdef USE_HTTPTOOLS
		std::vector<http_request_response *>	*header_array;
#endif
	public:
		stream(VOID) :
			data_array(new std::vector<data *>),
			stream_id(new id_info::id),
			source(NULL),
			destination(NULL),
#ifdef USE_HTTPTOOLS
			stream_end_size(0),
			header_array(new std::vector<http_request_response *>)
#else 
			stream_end_size(0)
#endif
		{
			if (stream_array == NULL) stream_array = new std::vector<stream *>;
			if (stream_sync == NULL) {
				stream_sync = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
				cInitializeCriticalSection(stream_sync);
			}

			// Add self to stream_array
			cEnterCriticalSection(stream_sync);
			stream_array->push_back(this);
			cLeaveCriticalSection(stream_sync);
		}

		~stream()
		{
			delete data_array;
#ifdef USE_HTTPTOOLS
			delete header_array;
#endif
			delete stream_id;

			for (std::vector<stream *>::iterator i = stream_array->begin();
				i != stream_array->end(); i++) {

				if (*i == this) {
					cEnterCriticalSection(stream_sync);
					stream_array->erase(i);
					cLeaveCriticalSection(stream_sync);
					break;
				}
			}
		}

		// Info
		id_info::id *stream::get_id(VOID) const
		{
			return this->stream_id;
		}

		enum {
			TYPE_SRC,
			TYPE_DEST
		};
		socket_data *stream::get_socket(__in const DWORD type) const
		{
			switch (type)
			{
			case TYPE_SRC:
				return source;
			case TYPE_DEST:
				return destination;
			default:
				return NULL;
			}
		}
	};


	// Bind class ////////////////////////////////////////////////////////////////
	class socket_bind {
	private:
		// Sockets
		SOCKET					a;
		SOCKET					b;
	
		// socket_data class (optional)
		socket_data				*sa;
		socket_data				*sb;

		// Bind state
		bool					bind_state;

		// Callbacks
		socket_tools::error_callback error_handler;

		// Defs
		typedef VOID			BIND_THREAD;

		// Buffers
		LPVOID					buffer_a;
		LPVOID					buffer_b;

		CRITICAL_SECTION		*lock;

		typedef bool			IO_MODE; //true: listen on a. false: listen on b.
		typedef struct {
			SOCKET				a;
			SOCKET				b;
			IO_MODE				mode;
			socket_bind			*This;

			types::TIME32		_io_thread_select_timeout_s;
			types::TIME32		_io_thread_select_timeout_ms;
		} IO_INFO, *PIO_INFO;
		PIO_INFO				io_info;
		HANDLE					io_thread_handle;
		// Obsolete
		static socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv socket_bind::bound_io_thread(PIO_INFO info);
		// New io_thread
		static socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv 
			socket_bind::io_thread(__in const PIO_INFO info);

		// Default handlers
		static VOID __declspec(noreturn) socket_bind::default_error_handler(__in const PIO_INFO info);
		static VOID __declspec(noreturn) socket_bind::default_data_handler(__in const PIO_INFO info,
			__in socket_tools::data *data_buffer);

		// Error handler. Cleans up and dispatches to error_handler callback
		VOID socket_bind::error_handler_local(VOID);

		// Data handler. Data is passed to this function. If it is NULL, it is bypassed.
		socket_tools::data_callback	data_handler;

	public:
		// If no data/error handlers are specified, this object is created for syncing
		HANDLE default_sync;

		HANDLE get_default_sync(VOID) const
		{
			return this->default_sync;
		}

	public:
		typedef struct socket_timeouts {
			types::TIME32		_timeout_io_thread_select_s;
			types::TIME32		_timeout_io_thread_select_ms;

			socket_timeouts()
			{
				_timeout_io_thread_select_s		= 0;
				_timeout_io_thread_select_ms	= 0;
			}
		} SOCKET_TIMEOUTS, *PSOCKET_TIMEOUTS;
		PSOCKET_TIMEOUTS		timing_params;

		// Ctors/Dtors. a is generally a client (obtained through listen), b is a server (obtained through connect).
		socket_bind(socket_data *a, socket_data *b, 
			error_callback error_handler, data_callback data_handler,
			PSOCKET_TIMEOUTS timings) :
			a(INVALID_SOCKET),
			b(INVALID_SOCKET),
			error_handler(error_handler), data_handler(data_handler),
			lock(NULL),
			io_thread_handle(INVALID_HANDLE_VALUE),
			sa(a), sb(b),
			buffer_a(NULL), buffer_b(NULL),
			io_info((PIO_INFO)mem::malloc(sizeof(IO_INFO))),
			timing_params(timings)
		{
			if (a->get_socket() == INVALID_SOCKET || b->get_socket() == INVALID_SOCKET) return;
			this->a = io_info->a = sa->get_socket();
			this->b = io_info->b = sb->get_socket();

			this->io_info->_io_thread_select_timeout_s	= timings->_timeout_io_thread_select_s;
			this->io_info->_io_thread_select_timeout_ms	= timings->_timeout_io_thread_select_ms;

			this->io_info->This		= this;
			this->io_thread_handle	= start_thread((LPTHREAD_START_ROUTINE)io_thread, this->io_info);

			
			/*
			this->lock			= (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
			cInitializeCriticalSection(this->lock);

			// Fix this shit
			this->info_a		= (PIO_INFO)mem::malloc(sizeof(IO_INFO));
			this->info_b		= (PIO_INFO)mem::malloc(sizeof(IO_INFO));
			info_a->a = info_b->a = this->a;
			info_a->b = info_b->b = this->b;
			info_a->This = info_b->This = this;
			info_a->mode		= true;
			info_b->mode		= false;

			this->thread_a		= start_thread((LPTHREAD_START_ROUTINE)bound_io_thread, info_a);
			this->thread_b		= start_thread((LPTHREAD_START_ROUTINE)bound_io_thread, info_b);		
				*/
			this->bind_state = true;
		}
		socket_bind(SOCKET a, SOCKET b, error_callback error_handler, data_callback data_handler) :
			a(a),
			b(b),
			error_handler(error_handler), data_handler(data_handler),
			lock(NULL),
			io_thread_handle(INVALID_HANDLE_VALUE),
			sa(NULL), sb(NULL),
			buffer_a(NULL), buffer_b(NULL),
			io_info((PIO_INFO)mem::malloc(sizeof(IO_INFO)))
		{
			if (a == INVALID_SOCKET || b == INVALID_SOCKET) return;
			this->a = io_info->a = a;
			this->b = io_info->b = b;

			this->io_info->This		= this;
			this->io_thread_handle	= start_thread((LPTHREAD_START_ROUTINE)io_thread, this->io_info);
			/*
			this->lock			= (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
			cInitializeCriticalSection(this->lock);

			this->info_a		= (PIO_INFO)mem::malloc(sizeof(IO_INFO));
			this->info_b		= (PIO_INFO)mem::malloc(sizeof(IO_INFO));
			info_a->a = info_b->a = this->a;
			info_a->b = info_b->b = this->b;
			info_a->This = info_b->This = this;
			info_a->mode		= true;
			info_b->mode		= false;

			this->thread_a		= start_thread((LPTHREAD_START_ROUTINE)bound_io_thread, info_a);
			this->thread_b		= start_thread((LPTHREAD_START_ROUTINE)bound_io_thread, info_b);
			*/
			this->bind_state = true;
		}
		~socket_bind(VOID)
		{
			//mem::free(this->lock);
			cTerminateThread(this->io_thread_handle, 0);
			//cCloseHandle(this->thread_a);
			//cCloseHandle(this->thread_b);

			if (this->sa != NULL) delete sa; 
			if (this->sb != NULL) delete sb;

			if (this->a != INVALID_SOCKET) closesocket(a);
			if (this->b != INVALID_SOCKET) closesocket(b);
		}
		// Creates threads
		//BIND_THREAD 

		// Sync
		VOID socket_bind::sync(bool state)
		{
			switch (state) 
			{
			case true:
				cEnterCriticalSection(this->lock);
				return;
			case false:
				cLeaveCriticalSection(this->lock);
				return;
			}
		}

		bool socket_bind::get_bind_state(VOID)
		{
			return this->bind_state;
		}
	};

	// Creates a listening interface, dispatches to a handler function
	typedef DWORD ST_LISTEN_ERROR;
	enum {
		ST_LISTEN_ERROR_OK,
		ST_LISTEN_ERROR_GENERAL_FAILURE,
		ST_LISTEN_ERROR_START_LISTENER_THREAD
	};

	static const UINT time_to_wait_createthread = TIME_TO_WAIT_CREATETHREAD;
	typedef struct listen_parameter {
		HANDLE						listener_thread;

		SOCKET						bind_socket;
		SOCKET						accept_socket;

		types::TIME32				wait_after_createthread;

		struct sockaddr				client_info;

		listen_parameter(VOID)
		{
			mem::zeromem(&this->client_info, sizeof(struct sockaddr));

			bind_socket				= INVALID_SOCKET;
			accept_socket			= INVALID_SOCKET;

			wait_after_createthread	= socket_tools::time_to_wait_createthread;
		}
	} LISTEN_PARAMETER, *PLISTEN_PARAMETER;

	typedef SOCKET_THREAD_ENTRY (__st_thread_conv *listen_callback)
		(__in const PLISTEN_PARAMETER parameters);

	ST_LISTEN_ERROR start_listener_thread(
		__in const listen_callback accept_handler,
		__in const WORD port);

	struct _socket_parm_internal {
		WORD						port;
		HANDLE						listener_handle;
		listen_callback				accept_handler;
		SOCKET						bind_socket;
		types::TIME32				wait_after_createthread;
	};
	static SOCKET_THREAD_ENTRY __st_thread_conv listener_thread(
		__in const struct socket_tools::_socket_parm_internal *internal_parameters);

	static UINT number_of_threads_started;
}