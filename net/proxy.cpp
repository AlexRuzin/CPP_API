// wait_and_read() should be calling socket_tools::wait_and_read

#define _WINSOCKAPI_

#include <Windows.h>
#include <WinSock2.h>
#include <random>
#include <vector>

#include "proxy.h"

#ifdef DEBUG_OUT
#include <stdio.h>
#endif

#ifdef DEBUG_OUT
#define D printf
#endif

#include "ip_tools.h"
#include "net/socket.h"

#include "common/mem.h"
#include "common/str.h"
#include "common/crypt.h"
#include "common/fs.h"

#include "debug/assert.h"
#include "debug/debug.h"

#pragma comment(lib, "ws2_32.lib")

using namespace proxy;

// Handles the SOCKS5 server
class proxy::socks_server {
private:
	// Bind socket
	SOCKET					bind_socket;

	// List info 
	proxy::PPROXY_LIST		entry;

	// Listener thread
	static proxy::PR_THREAD_ENTRY __declspec(noreturn) listener(__in const PSOCKET rx_socket);

	// Handles all I/O
	static proxy::PR_THREAD_ENTRY socks_server::instance_handler(__in const PSOCKET rx_socket);

public:
	// Parses ip/domain
	typedef DWORD ER_SERVER;
	enum {
		ER_SERVER_OK,
		ER_SERVER_FAIL
	};
	//socks_server::ER_SERVER socks_server::parse_ip_dom(__in LPCSTR name, __inout PTARGET_SERVER target);
	socks_server(proxy::PPROXY_LIST proxy_entry, WORD port, SOCKET tx_socket) :
		bind_socket(INVALID_SOCKET),
		entry(NULL)
	{
		this->bind_socket = tx_socket;
		this->entry = proxy_entry;

#ifndef SERVER_ONLY_MODE
		this->entry->known_target = proxy::known_file_list;
#endif

#ifdef SERVER_ONLY_MODE
#ifdef DEBUG_OUT
		DBGOUT("Proxy config:\n-> Server-only mode.\n-> No chaining\n-> SOCKS5 Relay.\n");
#endif
#endif

		cCreateThread(	NULL,
						0,
						(LPTHREAD_START_ROUTINE)listener,
						&this->bind_socket,
						0,
						NULL);
	}

	~socks_server(VOID)
	{
		if (this->bind_socket != INVALID_SOCKET) {
			closesocket(bind_socket);
		}
	}

	VOID socks_server::set_socket(const SOCKET tx_socket) 
	{
		this->bind_socket = tx_socket;
	}

};

// Main proxy instance
class proxy_instance {
public:
	typedef DWORD		SOCKET_ERROR_;
	typedef DWORD		PROXY_CLASS_ERROR;
	enum {
		ER_OK,
		ER_FAIL,
		ER_INVALID_SERVER, // general failure when the server doesn't response/function
		ER_SOCKET,
		ER_WSA,
		ER_CONNECT,
		ER_GREETING,
		ER_GREETING_RESPONSE,
		ER_SEND_CONNECT_INFO,
		ER_TEST_ATTEMPT,
		ER_ADJUST_DEST_INFO
	};

	// Proxy info
	typedef str_string PROXY_IP;;
	PROXY_IP			*proxy_ip;
	proxy::PROXY_PORT	proxy_port;	

#ifdef SERVER_ONLY_MODE //Used to connect to remote tor hidden service
	typedef str_string DOMAIN_NAME;
	DOMAIN_NAME			*domain_name;
#endif

	// Destination info
	typedef str_string DEST_IP;
	DEST_IP				*dest_ip;
	proxy::PROXY_PORT	dest_port;

	// Type of SOCKS server
	typedef DWORD SOCKS_TYPE;
	enum {
		SOCKS5,
		SOCKS4,
		SOCKS4a
	};

private:

	SOCKET				tx_socket;

public:
	// Waits for inbound data
	typedef struct {
		bool			wait_status;
		struct timeval	timed;
		fd_set			read_flags, 
						write_flags;
	} WAIT_STATE, *PWAIT_STATE;
	WAIT_STATE wait_state;
	typedef DWORD PROXY_WAIT_ERROR;
	enum {
		WAIT_RECEIVED,
		WAIT_TIMEOUT_OCCURRED,
		WAIT_FAILURE,
		WAIT_SOCKET_FAILURE,
		WAIT_NOTHING_RECEIVED
	};


	// Reads in input until timeout. Called by listener as well.
	static proxy_instance::PROXY_WAIT_ERROR proxy_instance::wait_and_read(__in const SOCKET tx_socket, 
		__out LPVOID *out, __out PUINT out_size);

public:
	proxy_instance(PPROXY_INFO proxy_info, PDEST_INFO dest_info) :
		proxy_ip(NULL),
		proxy_port(0),
		dest_ip(NULL),
		dest_port(0),
		tx_socket(INVALID_SOCKET)
	{
		proxy_ip		= proxy_info->ip_address;					// proxy server ip
		proxy_port		= proxy_info->port;							// proxy server port

#ifdef SERVER_ONLY_MODE

#ifdef DEBUG_OUT
		DBGOUT("proxy_instance: \n\tSOCKS5 Server: %s:%d\n\tDestination TOR address: %s:%d\n", 
			proxy_info->ip_address->to_lpstr(), proxy_info->port, 
			dest_info->domain->to_lpstr(), dest_info->port);
#endif
		domain_name			= dest_info->domain;
		dest_port			= dest_info->port;
#else

		if (dest_info != NULL && dest_info->ip_address != NULL) {	// If the instance is created by functional_servers, working server list
			dest_ip			= dest_info->ip_address;				// destination server ip
			dest_port		= dest_info->port;						// destination server port
		}
#endif

		mem::zeromem(&wait_state, sizeof(WAIT_STATE));
		wait_state.wait_status = false;
	}

	~proxy_instance(VOID) 
	{
		delete this->proxy_ip;
		delete this->dest_ip;

		if (this->tx_socket != INVALID_SOCKET) {
			closesocket(tx_socket);
		}
	}

	// Initialzes first connection
	proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socket(__inout WSADATA **wsadata, __out SOCKET *tx_socket);

	// Initializes the SOCKS5 relay. Takes dest as the destination server. proxy_address *address is the socks5 server.
#ifdef USE_SOCKS5
	proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socks5_relay(PSOCKET tx_socket);
#elif defined(USE_SOCKS4)
	proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socks4_relay(PSOCKET tx_socket);
#endif

	// Returns the active SOCKET
	SOCKET proxy_instance::get_socket(VOID) const;

	// Sets the active socket
	VOID proxy_instance::inherit_socket(const SOCKET tx_socket);

	// Test the proxy, download a page
	typedef DWORD PROXY_TEST_STATUS;
	enum {
		TEST_OK,
		TEST_FAIL
	};
	typedef struct {
		//str_string	*file;
		str_string	*host;
		WORD		port;
		str_string	*rx_string;		// The response must contain this data
	} PROXY_TEST_INFO, *PPROXY_TEST_INFO;
	proxy_instance::PROXY_TEST_STATUS proxy_instance::test_connection(proxy_instance::PPROXY_TEST_INFO info);

	// Adjusts the destination info - used by chaining
	proxy_instance::PROXY_CLASS_ERROR proxy_instance::adjust_dest(__in const proxy::PDEST_INFO new_info);

	// Closes the active SOCKET
	VOID close_socket(VOID);

	// Returns the port:ip string with \r\clos
	LPSTR proxy_instance::get_port_ip_string(str_string *ip, const WORD port);
};

// Contains a list of the functional servers, and info on the thread watcher
class proxy::functional_servers {
public:
	// Returns the working server vector array
	std::vector<proxy_instance *>		*get_working_servers(VOID);

	UINT								number_of_running_threads;
	UINT								possible_server_counter;
	
private:
	// Contains the raw list of servers (config, some may work, others may not)
	std::vector<PPROXY_ENTRY>			raw_server_list;		

	// Max number of threads
	const UINT							max_number_of_check_threads;

	// The actual list, containing running servers
	std::vector<proxy_instance *>		functional_server_list;

	// Entry point. Pass list of servers, starts enumeration
	typedef struct {
		std::vector<proxy_instance *>	*functional_server_list;
		std::vector<PPROXY_ENTRY>		possible_servers;
		PUINT							possible_server_counter;
		UINT							max_number_of_threads;
		PUINT							number_of_running_threads;
		CRITICAL_SECTION				*sync;
		proxy::functional_servers		*This;
	} SCAN_THREAD_INFO, *PSCAN_THREAD_INFO;
	static proxy::PR_THREAD_ENTRY __declspec(noreturn) functional_servers::get_active_list_thread(__inout PSCAN_THREAD_INFO thread_instance);
	typedef struct {
		std::vector<proxy_instance *>	*functional_server_list;
		PPROXY_ENTRY					raw_server;
		PUINT							number_of_running_threads;
		CRITICAL_SECTION				*sync;
		proxy::functional_servers		*This;
	} SPAWN_INFO, *PSPAWN_INFO;
	static proxy::PR_THREAD_ENTRY functional_servers::test_one_proxy(__inout PSPAWN_INFO thread_instance);

	// Synchronizes functional_server_list (adding removing functional servers)
	CRITICAL_SECTION					*func_serv_sync;

	// Populates the working proxy list
	LPSTR								working_proxies_target_file;
	typedef DWORD WORKING_ERROR;
	enum {
		WORKING_OK,
		WORKING_FAIL,
		WORKING_PARSER
	};
	functional_servers::WORKING_ERROR functional_servers::populate_working_servers(const proxy::PWORKING_PROXIES working_proxies);

	CRITICAL_SECTION					*thread_state_sync;
	VOID functional_servers::thread_state(bool state, proxy::functional_servers *This)
	{
		switch(state)
		{
		case true:
			cEnterCriticalSection(This->thread_state_sync);
			return;
		case false:
			cLeaveCriticalSection(This->thread_state_sync);
			return;
		}
	}
public:
	functional_servers::WORKING_ERROR functional_servers::add_working_server(proxy_instance *instance);
	LPSTR functional_servers::get_working_proxies_target_file(VOID) const
	{
		return this->working_proxies_target_file;
	}

public:
	// Pass raw server list
	functional_servers(std::vector<PPROXY_ENTRY> raw_list, proxy::PWORKING_PROXIES working_proxies) :
		max_number_of_check_threads(NUMBER_OF_SCANNING_THREADS),
		number_of_running_threads(0),
		possible_server_counter(0)
	{
		// Populate the working proxies
		if (working_proxies->buffer != NULL && working_proxies->size != 0) {
#ifdef DEBUG_OUT
			D("[+] Working proxies buffer found, parsing\n");
#endif
			WORKING_ERROR working_status = populate_working_servers(working_proxies);
			if (working_status != WORKING_OK) {
#ifdef DEBUG_OUT
				D("[!] Failed to parse working buffer\n");
#endif
			}
		}
		this->working_proxies_target_file = working_proxies->target_file;

		this->raw_server_list = raw_list;

		this->func_serv_sync = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
		cInitializeCriticalSection(func_serv_sync);
		
		this->thread_state_sync = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
		cInitializeCriticalSection(this->thread_state_sync);

		PSCAN_THREAD_INFO thread_info			= (PSCAN_THREAD_INFO)mem::malloc(sizeof(SCAN_THREAD_INFO));
		thread_info->sync						= this->func_serv_sync;
		thread_info->This						= this;
		thread_info->functional_server_list		= &this->functional_server_list;
		thread_info	->possible_servers			= raw_list;
		thread_info->max_number_of_threads		= max_number_of_check_threads;
		thread_info->possible_server_counter	= &possible_server_counter;
		thread_info->number_of_running_threads	= &number_of_running_threads;
		HANDLE new_thread = CreateThread(		NULL,
												0,
												(LPTHREAD_START_ROUTINE)get_active_list_thread,
												(LPVOID)thread_info,
												NULL,
												0);
#ifdef DEBUG_OUT
		ASSERT(new_thread != NULL, "[!] Failure in creating get_active_list_thread");
		D("[+] Starting thread watchdog\n");
#endif				
	}

	VOID functional_servers::sync(bool enter)
	{
		switch (enter) 
		{
		case true:
			cEnterCriticalSection(this->func_serv_sync);
		case false:
			cLeaveCriticalSection(this->func_serv_sync);
		}
	}

};

functional_servers::WORKING_ERROR functional_servers::populate_working_servers(const proxy::PWORKING_PROXIES working_proxies)
{
	if (working_proxies->buffer == NULL || working_proxies->size == 0) return WORKING_FAIL;

#ifdef DEBUG_OUT
	D("[+] Populating known servers\n");
#endif

	// Parse input proxy_instance(PPROXY_INFO proxy_info, PDEST_INFO dest_info) :
	str_string *input_list = new str_string(str_string::MODE_SPLIT_LINE, (LPCSTR)working_proxies->buffer, working_proxies->size);
	str::PLINE current_line = input_list->get_first_line();
	while (current_line != NULL) {
		str_string *tmp_string		= new str_string(current_line->line_buffer);
		Ptr<std::vector<LPSTR>> Tmp	= tmp_string->split_string_by_terminatorA(NULL, ":", str::lenA(":"));

		PPROXY_INFO proxy_info		= (PPROXY_INFO)mem::malloc(sizeof(PROXY_INFO));
		proxy_info->ip_address		= (PROXY_ADDRESS)new str_string((LPSTR)Tmp->at(0));
		proxy_info->port			= (PROXY_PORT)atoi((const char *)Tmp->at(1));

		proxy_instance *instance	= new proxy_instance(proxy_info, NULL);
		
		this->functional_server_list.push_back(instance);

#ifdef DEBUG_OUT
		D("[+] Server loaded from working list: %s:%d\n", proxy_info->ip_address->to_lpstr(), proxy_info->port);
#endif

		delete tmp_string;
		current_line = current_line->next_line;
	}
#ifdef DEBUG_OUT
	D("[+] %d working servers available\n", this->functional_server_list.size());
#endif

	/*
	str_string *input_list = new str_string(str_string::MODE_SPLIT_LINE, (LPCSTR)list->buffer, list->size);
	std::vector<PPROXY_ENTRY> entries;
	str::PLINE current_line = input_list->get_first_line();
	while (current_line != NULL) {
		PPROXY_ENTRY chain	= (PPROXY_ENTRY)mem::malloc(sizeof(PROXY_ENTRY));
		chain->buffer		= (PROXY_ADDRESS)new str_string(current_line->line_buffer);
		entries.push_back(chain);

		current_line = current_line->next_line;
	}

	// Parse IP:Port
	for (UINT i = 0; i < entries.capacity(); i++) {
		std::vector<LPSTR> tmp		= entries.at(i)->buffer->split_string_by_terminatorA(NULL, ":", str::lenA(":"));
		if (tmp.capacity() != 2) continue;
		entries.at(i)->ip_address	= (PROXY_ADDRESS)new str_string((LPSTR)tmp.at(0));
		entries.at(i)->port			= (PROXY_PORT)atoi((const char *)tmp.at(1)); // Network byte order is done later

#ifdef DEBUG_OUT
		D("[+] Loaded server from config: %s:%d\n", entries.at(i)->ip_address->to_lpstr(), entries.at(i)->port);
#endif
	}*/

	return WORKING_OK;
}

functional_servers::WORKING_ERROR functional_servers::add_working_server(proxy_instance *instance) 
{
	if (this->working_proxies_target_file == NULL) return WORKING_FAIL;

	LPSTR buffer = instance->get_port_ip_string(instance->proxy_ip, instance->proxy_port);

	LPSTR read_buffer;
	UINT read_buffer_size;
	BOOL read_status = fs::read_raw_into_buffer(this->working_proxies_target_file, &read_buffer_size, (LPVOID *)&read_buffer);
	if (read_status == FALSE) {
		// File needs to be created
		BOOL write_status = fs::write_raw_to_disk(this->working_proxies_target_file, (PDWORD)buffer, str::lenA(buffer));
		if (write_status == FALSE) {
			mem::free(buffer);
			return WORKING_FAIL;
		}

		mem::free(buffer);
		return WORKING_OK;
	}

	// Check if there exists a similar string
	PCHAR ptr;
	if (str::find_sequence_pointerA(read_buffer, str::lenA(read_buffer), buffer, str::lenA(buffer), &ptr) == ER_STR_OK) {
		// Exists in the file
		mem::free(buffer);
		mem::free(read_buffer);
		return WORKING_OK;
	}
	BOOL append_status = fs::append_raw_to_disk(this->working_proxies_target_file, (PDWORD)buffer, str::lenA(buffer));


	mem::free(buffer);
	return WORKING_OK;
}

std::vector<proxy_instance *> *functional_servers::get_working_servers(VOID) 
{
	std::vector<proxy_instance *> *list;
	cEnterCriticalSection(this->func_serv_sync);
	list = &this->functional_server_list;
	cLeaveCriticalSection(this->func_serv_sync);

	return list;
}

proxy::PR_THREAD_ENTRY functional_servers::test_one_proxy(__inout PSPAWN_INFO thread_instance)
{
#ifdef DEBUG_OUT_
	printf("Starting scan thread [%d]: %s\n", *thread_instance->number_of_running_threads, thread_instance->raw_server->buffer->to_lpstr());
#endif

#ifdef DEBUG_OUTVERBOSE
	D("[+] Trying %s:%d\n", thread_instance->raw_server->ip_address->to_lpstr(), thread_instance->raw_server->port);
#endif

	if (proxy::timing_test_proxy != 0) {
		cSleep(proxy::timing_test_proxy);
	}

	proxy::PDEST_INFO dest_info		= (PDEST_INFO)mem::malloc(sizeof(DEST_INFO));
	dest_info->ip_address			= (DEST_ADDRESS)new str_string(proxy::test_host);
	dest_info->port					= (DEST_PORT)proxy::test_port;
	proxy::PPROXY_INFO proxy_info	= (PPROXY_INFO)mem::malloc(sizeof(PROXY_INFO));
	proxy_info->ip_address			= new str_string(thread_instance->raw_server->ip_address->to_lpstr());
	proxy_info->port				= thread_instance->raw_server->port;
	proxy_instance *instance		= new proxy_instance(proxy_info, dest_info);

#ifdef DEBUG_OUT_
	D("Starting test thread (%d run) on: dest: %s:%d\tproxy: %s:%d\n", *thread_instance->number_of_running_threads, 
																					dest_info->ip_address->to_lpstr(),
																					dest_info->port,
																					proxy_info->ip_address->to_lpstr(),
																					proxy_info->port);
#endif

	SOCKET tx_socket;
	proxy_instance::PROXY_CLASS_ERROR socket_status	= instance->init_socket(&proxy::wsadata, &tx_socket);
	if (socket_status != proxy_instance::ER_OK) {
		delete instance;
#ifdef DEBUG_OUT_
		D("Thread exiting\n");
#endif
#ifdef DEBUG_OUTVERBOSE
		D("[+] [%s:%d] Socket failure\n", thread_instance->raw_server->ip_address->to_lpstr(), thread_instance->raw_server->port);
#endif
		thread_instance->This->thread_state(true, thread_instance->This);
		if (thread_instance->number_of_running_threads != 0) InterlockedDecrement(thread_instance->number_of_running_threads);
		thread_instance->This->thread_state(false, thread_instance->This);
		return;
	}

#if defined (USE_SOCKS5)
	proxy_instance::PROXY_CLASS_ERROR init_status	= instance->init_socks5_relay(&tx_socket);
#elif defined (USE_SOCKS4)
	proxy_instance::PROXY_CLASS_ERROR init_status	= instance->init_socks4_relay(&tx_socket);
#endif
	if (init_status != proxy_instance::ER_OK) {
#ifdef DEBUG_OUTVERBOSE
		D("[+] [%s:%d] Relay failure\n", thread_instance->raw_server->ip_address->to_lpstr(), thread_instance->raw_server->port);
#endif
		delete instance;
		thread_instance->This->thread_state(true, thread_instance->This);
		if (thread_instance->number_of_running_threads != 0) InterlockedDecrement(thread_instance->number_of_running_threads);
		thread_instance->This->thread_state(false, thread_instance->This);
		return;
	}

	proxy_instance::PROXY_TEST_INFO test_info;
	mem::zeromem(&test_info, sizeof(proxy_instance::PROXY_TEST_INFO));
	test_info.host		= new str_string(proxy::test_host);
	test_info.port		= proxy::test_port;
	test_info.rx_string	= new str_string(proxy::test_look_for);
	proxy_instance::PROXY_TEST_STATUS test_http_status = instance->test_connection(&test_info);
	if (test_http_status != proxy_instance::TEST_OK) {
#ifdef DEBUG_OUTVERBOSE
		D("[+] [%s:%d] Test failure\n", thread_instance->raw_server->ip_address->to_lpstr(), thread_instance->raw_server->port);
#endif
		delete test_info.host;
		delete test_info.rx_string;
		delete instance;
		thread_instance->This->thread_state(true, thread_instance->This);
		if (thread_instance->number_of_running_threads != 0) InterlockedDecrement(thread_instance->number_of_running_threads);
		thread_instance->This->thread_state(false, thread_instance->This);
		return;
	}

	cEnterCriticalSection(thread_instance->sync);
	// Check if the server exist already
	for (UINT i = 0; i < thread_instance->functional_server_list->size(); i++) {
		if (!mem::compare(thread_instance->functional_server_list->at(i)->proxy_ip->to_lpstr(), proxy_info->ip_address->to_lpstr(), 
			proxy_info->ip_address->lenA()) 
			&& (thread_instance->functional_server_list->at(i)->proxy_port == thread_instance->raw_server->port)) {
				cLeaveCriticalSection(thread_instance->sync);
#ifdef DEBUG_OUT
				D("[+] Duplicate found %s:%d.\n", thread_instance->functional_server_list->at(i)->proxy_ip->to_lpstr(),
					thread_instance->functional_server_list->at(i)->proxy_port);
#endif
				delete instance;
				thread_instance->This->thread_state(true, thread_instance->This);
				if (thread_instance->number_of_running_threads != 0) InterlockedDecrement(thread_instance->number_of_running_threads);
				thread_instance->This->thread_state(false, thread_instance->This);
				return;
		}
	}
	proxy::working_servers->add_working_server(instance);
#ifdef DEBUG_OUT
	D("[+] New server added: %s:%d\n", thread_instance->raw_server->ip_address->to_lpstr(), thread_instance->raw_server->port);
#endif
	thread_instance->functional_server_list->push_back(instance);
	thread_instance->functional_server_list->back()->close_socket(); // Closes the socket, prepares for chaining
	cLeaveCriticalSection(thread_instance->sync);
	thread_instance->This->thread_state(true, thread_instance->This);
	if (thread_instance->number_of_running_threads != 0) InterlockedDecrement(thread_instance->number_of_running_threads);
	thread_instance->This->thread_state(false, thread_instance->This);
	return;
}

// Returns ALL active proxies. Init and test
DWORD number_of_tested_servers = 0;
proxy::PR_THREAD_ENTRY __declspec(noreturn) functional_servers::get_active_list_thread(__inout PSCAN_THREAD_INFO thread_instance)
{
#ifdef DEBUG_OUT
	ASSERT(thread_instance != NULL, "Invalid parameter: PSCAN_THREAD_INFO @ get_active_list_thread()");
#endif

	*thread_instance->number_of_running_threads	= 0;
	while (TRUE) {
next_cycle:
		if (thread_instance->possible_servers.size() == thread_instance->functional_server_list->size()) {
			// All servers are functional
			Sleep(1000);
			continue;
		}

		if (*thread_instance->possible_server_counter >= thread_instance->possible_servers.size()) {
#ifdef SCAN_MODE
#ifdef DEBUG_OUT
			D("[+] Scanned %d of %d\n", thread_instance->possible_servers.size(), thread_instance->possible_servers.size());
#endif
#endif
			cSleep(INFINITE);
			*thread_instance->possible_server_counter = 0;
			while (*thread_instance->number_of_running_threads != 0) {
				Sleep(1000);
			}
#ifdef DEBUG_OUT
			D("[+] Cycling through proxies again\n");
#endif			
		}

		for (UINT i = 0; i < thread_instance->functional_server_list->size(); i++) {
			//PPROXY_ENTRY tmp_entry = thread_instance->possible_servers.at(*thread_instance->possible_server_counter);
			//proxy_instance *tmp_instance = thread_instance->functional_server_list->at(i);

			if (!mem::compare(thread_instance->functional_server_list->at(i)->proxy_ip->to_lpstr(),
				thread_instance->possible_servers.at(*thread_instance->possible_server_counter)->ip_address->to_lpstr(), 
				thread_instance->functional_server_list->at(i)->proxy_ip->lenA()) &&
				(thread_instance->functional_server_list->at(i)->proxy_port == 
				thread_instance->possible_servers.at(*thread_instance->possible_server_counter)->port)) {
#ifdef DEBUG_OUT
				D("[!] Server %s:%d already in functional list\n", thread_instance->functional_server_list->at(i)->proxy_ip->to_lpstr(),
					thread_instance->functional_server_list->at(i)->proxy_port);
#endif
				*thread_instance->possible_server_counter = *thread_instance->possible_server_counter + 1;
				goto next_cycle;
			}
		}

		if (*thread_instance->number_of_running_threads < thread_instance->max_number_of_threads) {
			// Create new thread
			PSPAWN_INFO spawn_info					= (PSPAWN_INFO)mem::malloc(sizeof(SPAWN_INFO));
			spawn_info->sync						= thread_instance->sync;
			spawn_info->raw_server					= thread_instance->possible_servers.at(*thread_instance->possible_server_counter);
			spawn_info->functional_server_list		= thread_instance->functional_server_list;
			spawn_info->number_of_running_threads	= thread_instance->number_of_running_threads;
			spawn_info->This						= thread_instance->This;
			*thread_instance->possible_server_counter = *thread_instance->possible_server_counter + 1;
			spawn_info->This->thread_state(true, spawn_info->This);
			InterlockedIncrement(thread_instance->number_of_running_threads);
			spawn_info->This->thread_state(false, spawn_info->This);
			HANDLE new_thread = CreateThread(	NULL,
												0,
												(LPTHREAD_START_ROUTINE)test_one_proxy,
												(LPVOID)spawn_info,
												0,
												NULL);
			cCloseHandle(new_thread);
			//Sleep(INFINITE);
			number_of_tested_servers++;
			if (!(number_of_tested_servers & 0x0000fff)) {
#ifdef DEBUG_OUT
				D("[+] Tested %d servers. %d running threads.\n", 
					number_of_tested_servers, *thread_instance->number_of_running_threads);
#endif
			}
#ifdef DEBUG_OUT
			ASSERT(new_thread != NULL, "[!] Failure in spawning test_one_proxy");
#endif
			//printf(".");
		}
		if (proxy::timing_create_scan != 0) {
			cSleep(proxy::timing_create_scan);
		}
	}

	/*
	for (UINT i = 0; i < entries.capacity(); i++) {
		proxy::PDEST_INFO dest_info		= (PDEST_INFO)mem::malloc(sizeof(DEST_INFO));
		dest_info->ip_address			= (DEST_ADDRESS)new str_string(test_local_host);
		dest_info->port					= entries.at(i)->port;
		proxy::PPROXY_INFO proxy_info	= (PPROXY_INFO)mem::malloc(sizeof(PROXY_INFO));
		proxy_info->ip_address			= entries.at(i)->ip_address;
		proxy_info->port				= entries.at(i)->port;
		proxy_instance *instance		= new proxy_instance(proxy_info, dest_info);

		SOCKET tx_socket;
		proxy_instance::PROXY_CLASS_ERROR socket_status	= instance->init_socket(&proxy::wsadata, &tx_socket);
		if (socket_status != proxy_instance::ER_OK) {
			delete instance;
			continue;
		}

		proxy_instance::PROXY_CLASS_ERROR init_status	= instance->init_socks5_relay(instance->get_socket());
		if (init_status != proxy_instance::ER_OK) {
			delete instance;
			continue;
		}

		
		//proxy::functional_server_list.push_back(instance);
	}*/
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
LPSTR proxy_instance::get_port_ip_string(str_string *ip, const WORD port)
{
	if (ip == NULL || port == 0) return NULL;

	CHAR port_buffer[1024];
	_itoa_s((int)port, port_buffer, 10);
	LPSTR port_ip_buffer = (LPSTR)mem::malloc(ip->lenA() + str::lenA(":") + str::lenA(port_buffer) + str::lenA("\r\n") + str::ASCII_CHAR);
	mem::copy(port_ip_buffer, ip->to_lpstr(), ip->lenA());
	*(PBYTE)&port_ip_buffer[str::lenA(port_ip_buffer)] = ':';
	mem::copy(&port_ip_buffer[str::lenA(port_ip_buffer)], port_buffer, str::lenA(port_buffer));
	*(PWORD)&port_ip_buffer[str::lenA(port_ip_buffer)] = '\r\n';

	return port_ip_buffer;
}

VOID proxy_instance::inherit_socket(const SOCKET tx_socket)
{
	this->tx_socket = tx_socket;

	return;
}

VOID proxy_instance::close_socket(VOID)
{
	if (this->tx_socket != INVALID_SOCKET) {
		closesocket(this->tx_socket);
		this->tx_socket = INVALID_SOCKET;
	}
	
	return;
}

proxy_instance::PROXY_CLASS_ERROR proxy_instance::adjust_dest(__in const proxy::PDEST_INFO new_info)
{
	if (new_info == NULL) return ER_ADJUST_DEST_INFO;

	if (this->dest_ip != NULL) {
		delete this->dest_ip;
		this->dest_port			= 0;
	}

	this->dest_ip			= new_info->ip_address;
	this->dest_port			= new_info->port;

	mem::free(new_info);

	return proxy_instance::ER_OK;
}

proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socket(__inout WSADATA **wsadata, __out SOCKET *tx_socket)
{
#ifndef SERVER_ONLY_MODE
	if (proxy::wsa_state == false) {
		*wsadata = (WSADATA *)mem::malloc(sizeof(WSADATA));
		ERROR_CODE wsa_status = WSAStartup(MAKEWORD(2, 2), *wsadata);
		if (wsa_status) {
			mem::free(*wsadata);
			*tx_socket = this->tx_socket = INVALID_SOCKET;
			return ER_WSA;
		}
		proxy::wsa_state = true;
	}
#endif

	SOCKET new_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (new_socket == INVALID_SOCKET) {
		*tx_socket = this->tx_socket = INVALID_SOCKET;
		return ER_SOCKET;
	}

	struct sockaddr_in proxyaddr;
	mem::zeromem(&proxyaddr, sizeof(struct sockaddr_in));
	proxyaddr.sin_family			= AF_INET;
	proxyaddr.sin_addr.S_un.S_addr	= inet_addr((const char *)this->proxy_ip->to_lpstr());
	proxyaddr.sin_port				= htons(this->proxy_port);
	SOCKET_ERROR_ socket_status		= (SOCKET_ERROR_)connect(new_socket, (struct sockaddr *)&proxyaddr, sizeof(proxyaddr));
	if (socket_status == SOCKET_ERROR) {
		close_socket();
		*tx_socket = this->tx_socket = INVALID_SOCKET;
		return ER_CONNECT;
	}

	*tx_socket		= new_socket;
	this->tx_socket = new_socket;

	return ER_OK;
}

#ifdef USE_SOCKS4
proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socks4_relay(PSOCKET tx_socket)
{
	if (*tx_socket == INVALID_SOCKET) return ER_FAIL;

	struct socks4_request request;
	mem::zeromem(&request, sizeof(struct socks4_request));
	request.version			= proxy::socks4_version;
	request.command_code	= proxy::socks4_command_code_stream;
	request.ip				= (proxy::dest_ip)inet_addr(this->dest_ip->to_lpstr());
	request.port			= (proxy::DEST_PORT)htons(this->dest_port);
	INT	bytes_sent			= send(*tx_socket, (const char *)&request, sizeof(struct socks4_request), 0);
	if (bytes_sent != sizeof(struct socks4_request) || *tx_socket == INVALID_SOCKET) {
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING;
	}

	LPVOID response				= NULL;
	UINT response_length		= 0;
	PROXY_WAIT_ERROR rx_status	= wait_and_read(*tx_socket, &response, &response_length);
	if (rx_status != WAIT_RECEIVED || response == NULL || response_length == 0) {
		if (response != NULL) mem::free(response);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING_RESPONSE;
	}
	proxy::socks4_response *response_struct = (proxy::socks4_response *)response;
	if (response_struct->null != proxy::socks4_response_null || response_struct->status != proxy::socks4_request_granted) {
		if (response != NULL) mem::free(response);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING_RESPONSE;
	}

	return ER_OK;
}
#endif

#ifdef USE_SOCKS5
proxy_instance::PROXY_CLASS_ERROR proxy_instance::init_socks5_relay(PSOCKET tx_socket)
{
	INT bytes_sent = send(*tx_socket, (const char *)&socks5_greeting, 3, 0);
	if (bytes_sent != sizeof(socks5_greeting)) {
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING;
	}

	LPVOID server_auth_type_response	= NULL;
	UINT response_length				= 0;
	socket_tools::ER_WAIT_AND_READ rx_status = socket_tools::wait_and_read(*tx_socket, 10, 0, &server_auth_type_response, &response_length);
	if (rx_status != WAIT_RECEIVED) {
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING;
	}

	// Check response
	proxy::socks5_greeting_response *greet_response = (proxy::socks5_greeting_response *)server_auth_type_response;
	if (greet_response->version != proxy::socks5_version || greet_response->auth_method != socks5_auth_method) {
		mem::free(server_auth_type_response);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_GREETING;
	}
	mem::free(server_auth_type_response);

	// Send connection info
#ifdef SERVER_ONLY_MODE
	proxy::socks5_client_connection_request_domain *connection_request = (proxy::socks5_client_connection_request_domain *)
		mem::malloc(sizeof(proxy::socks5_client_connection_request_domain) + sizeof(WORD) + this->domain_name->lenA());
	connection_request->version			= proxy::socks5_version;
	connection_request->command_code	= proxy::socks5_command_code;
	connection_request->address_type	= proxy::socks5_address_type_dom;
	connection_request->name_length		= this->domain_name->lenA();
	mem::copy((LPVOID)((DWORD_PTR)connection_request + sizeof(proxy::socks5_client_connection_request_domain)),
		this->domain_name->to_lpstr(), this->domain_name->lenA());
	*(PWORD)((DWORD_PTR)connection_request + sizeof(proxy::socks5_client_connection_request_domain) + 
		this->domain_name->lenA())		= htons(this->dest_port);
	bytes_sent							= send(*tx_socket, (const char *)connection_request, 
		(int)(sizeof(proxy::socks5_client_connection_request_domain) + this->domain_name->lenA() + sizeof(WORD)), 0);
	if (bytes_sent != (sizeof(proxy::socks5_client_connection_request_domain) + this->domain_name->lenA() + sizeof(WORD))) {
		mem::free(connection_request);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_SEND_CONNECT_INFO;
	}

	proxy::socks5_client_connection_response *server_connect_response;
	UINT server_response_length;
	response_length						= 0;
	rx_status							= socket_tools::wait_and_read(*tx_socket, 
		proxy::timing_local_connect_s , proxy::timing_local_connect_ms, 
		(LPVOID *)&server_connect_response, &server_response_length);
	if (rx_status != WAIT_RECEIVED || server_connect_response == NULL ||
		server_connect_response->version != proxy::socks5_version ||
		server_connect_response->status != proxy::socks5_status_ok ||
		server_connect_response->address_type != proxy::socks5_address_type_ip) {

#ifdef DEBUG_OUT
		if (server_connect_response == NULL) {
			DBGOUT("[!] No response from SOCKS5 received\n");
		} else {
			DBGOUT("[!] Error code: 0x%02x\n", server_connect_response->status);
		}
#endif
		mem::free(server_connect_response);
		mem::free(connection_request);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_SEND_CONNECT_INFO;
	}

	mem::free(server_connect_response);
	mem::free(connection_request);
	return ER_OK;
#else
	proxy::socks5_client_connection_request *connection_request = (proxy::socks5_client_connection_request *)
		mem::malloc(sizeof(proxy::socks5_client_connection_request));
	connection_request->version			= proxy::socks5_version;
	connection_request->command_code	= proxy::socks5_command_code;
	connection_request->address_type	= proxy::socks5_address_type_ip;
	connection_request->ip				= (proxy::dest_ip)inet_addr(this->dest_ip->to_lpstr());
	connection_request->port			= htons(this->dest_port);
	bytes_sent							= send(*tx_socket, (const char *)connection_request, 
		sizeof(proxy::socks5_client_connection_request), 0);
	if (bytes_sent != sizeof(proxy::socks5_client_connection_request)) {
		mem::free(connection_request);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_SEND_CONNECT_INFO;
	}

	proxy::socks5_client_connection_response *server_connect_response		= NULL;
	response_length						= 0;
	rx_status							= wait_and_read(*tx_socket, (LPVOID *)&server_connect_response, &response_length);
	if (rx_status != WAIT_RECEIVED || server_connect_response == NULL ||
		server_connect_response->version != proxy::socks5_version ||
		server_connect_response->status != proxy::socks5_status_ok ||
		server_connect_response->address_type != proxy::socks5_address_type_ip) {
		mem::free(connection_request);
		closesocket(*tx_socket);
		this->tx_socket = *tx_socket = INVALID_SOCKET;
		return ER_SEND_CONNECT_INFO;
	}

	mem::free(connection_request);
	return ER_OK;
#endif
}
#endif

proxy_instance::PROXY_WAIT_ERROR proxy_instance::wait_and_read(__in const SOCKET tx_socket, 
	__out LPVOID *out, __out PUINT out_size)
{
	if (tx_socket == INVALID_SOCKET) return WAIT_SOCKET_FAILURE;
	*out		= NULL;
	*out_size	= 0;

	/*
	if (this->wait_state.wait_status == false) {
		this->wait_state.timed.tv_sec	= proxy::timeout_s_;
		this->wait_state.timed.tv_usec	= proxy::timeout_ms_;
		FD_ZERO(&(this->wait_state.read_flags));
		FD_ZERO(&(this->wait_state.write_flags));
		FD_SET(0, &(this->wait_state.write_flags));
		FD_SET(tx_socket, &(this->wait_state.read_flags));
		this->wait_state.wait_status = true;
	}*/
	struct timeval timed;
	mem::zeromem(&timed, sizeof(struct timeval));
	timed.tv_sec			= proxy::timeout_s_;
	timed.tv_usec			= proxy::timeout_ms_;
	fd_set read_flags, write_flags;
	FD_ZERO(&read_flags);
	FD_ZERO(&write_flags);
	FD_SET(0, &write_flags);
	FD_SET(tx_socket, &read_flags);

	PUCHAR rx_buffer		= (PUCHAR)mem::malloc(str::ASCII_CHAR);
	UINT rx_buffer_length	= str::ASCII_CHAR;
	while (TRUE) {
		INT select_status = select(tx_socket, &read_flags, 
			NULL, NULL, &timed);
		if (!select_status) break;

		UCHAR byte	= 0;
		UINT rxd	= recv(tx_socket, (char *)&byte, sizeof(UCHAR), 0);
		if (rxd != sizeof(UCHAR)) break;

		rx_buffer[rx_buffer_length - 1] = byte;
		PUCHAR new_buffer = (PUCHAR)mem::malloc(rx_buffer_length + rxd);
		mem::copy(new_buffer, rx_buffer, rx_buffer_length);
		mem::free(rx_buffer);
		rx_buffer = new_buffer;
		rx_buffer_length++;
	}
	if (rx_buffer_length == 1) {
		mem::free(rx_buffer);
		return WAIT_NOTHING_RECEIVED;
	}

	*out		= rx_buffer;
	*out_size	= rx_buffer_length;

	return WAIT_RECEIVED;
}

SOCKET proxy_instance::get_socket(VOID) const
{
	return this->tx_socket;
}

proxy_instance::PROXY_TEST_STATUS proxy_instance::test_connection(proxy_instance::PPROXY_TEST_INFO info)
{
	if (info == NULL || info->host == NULL || info->rx_string == NULL || info->port == 0 || this->tx_socket == INVALID_SOCKET) return TEST_FAIL;

	// Prepare & send buffer
	PCHAR tx_buffer = (PCHAR)mem::malloc(str::lenA(proxy::test_http_header) + 
		str::lenA(this->dest_ip->to_lpstr()) + str::lenA(proxy::test_header_end) + str::ASCII_CHAR);
	mem::copy(tx_buffer, proxy::test_http_header, str::lenA(proxy::test_http_header));
	mem::copy(&tx_buffer[str::lenA(proxy::test_http_header)], this->dest_ip->to_lpstr(), this->dest_ip->lenA());
	mem::copy(&tx_buffer[str::lenA(tx_buffer)], proxy::test_header_end, str::lenA(proxy::test_header_end));
	
	INT send_status = send(this->tx_socket, (const char *)tx_buffer, str::lenA(tx_buffer), 0);
	if (send_status != str::lenA(tx_buffer)) {
		closesocket(this->tx_socket);
		this->tx_socket = INVALID_SOCKET;
		mem::free(tx_buffer);
		return TEST_FAIL;
	}
	LPVOID rx_buffer;
	UINT received_bytes;
	PROXY_WAIT_ERROR wait_status = wait_and_read(this->tx_socket, (LPVOID *)&rx_buffer, &received_bytes);
	if (wait_status != WAIT_RECEIVED) {
		closesocket(this->tx_socket);
		this->tx_socket = INVALID_SOCKET;
		mem::free(tx_buffer);
		return TEST_FAIL;
	}

	LPSTR ptr;
	if (str::find_sequence_pointerA((LPCSTR)rx_buffer, received_bytes, info->rx_string->to_lpstr(), 
		info->rx_string->lenA(), &ptr) == ER_STR_NO_SUCH_SEQUENCE) {
		closesocket(this->tx_socket);
		this->tx_socket = INVALID_SOCKET;
		mem::free(tx_buffer);
		mem::free(rx_buffer);
		return TEST_FAIL;
	}

	closesocket(this->tx_socket);
	this->tx_socket = INVALID_SOCKET;
	mem::free(rx_buffer);
	mem::free(tx_buffer);
	return TEST_OK;
}
/*
ER_PROXY proxy::add_to_chain(__in proxy::PPROXY_INFO info, __out SOCKET *out_socket)
{
	// Test the socket
	proxy_instance *instance = new proxy_instance(info);
	SOCKET tx_socket = INVALID_SOCKET;
	proxy_instance::PROXY_CLASS_ERROR test_status = instance->init_socket(&wsadata, &tx_socket);
	if (test_status != proxy_instance::ER_OK) {
		delete instance;
		return proxy_instance::ER_INVALID_SERVER;
	}

	// Attempt to initialize SOCKS5
	str_string *dest = new str_string(proxy::test_local_host);
	test_status = instance->init_socks5_relay(instance->get_socket(), dest);
	if (test_status != proxy_instance::ER_OK) {
		delete instance;
		delete dest;
		if (instance->get_socket() != INVALID_SOCKET) closesocket(instance->get_socket());
		return proxy_instance::ER_INVALID_SERVER;
	}

	// SOCKS5 circuit ready, try to download a page
	proxy_instance::PROXY_TEST_INFO test_info;
	mem::zeromem(&test_info, sizeof(proxy_instance::PROXY_TEST_INFO));
	test_info.host		= new str_string(proxy::test_local_host);
	test_info.port		= proxy::test_cmyip_port;
	test_info.rx_string	= new str_string(proxy::test_local_look_for);
	proxy_instance::PROXY_TEST_STATUS test_http_status = instance->test_connection(&test_info);
	if (test_http_status != proxy_instance::TEST_OK) {
		delete test_info.host;
		delete test_info.rx_string;
		closesocket(instance->get_socket());
		delete instance;
		delete dest;
		return proxy_instance::ER_INVALID_SERVER;
	}


	delete test_info.host;
	delete test_info.rx_string;
	return ER_PROXY_OK;
}*/

proxy::PPROXY_ENTRY proxy::get_random_proxy(std::vector<proxy::PPROXY_ENTRY> entries)
{
	return (PPROXY_ENTRY)entries.at(crypt::generate_random_byte_range(entries.size()));
}

proxy::PR_INT32 proxy::get_current_test_proxy(__in std::vector<PPROXY_ENTRY> entries)
{
	if ( entries.back() == entries.at(proxy::current_entry)) {
		current_entry = 0;
	}
	return 0;
}

SOCKET proxy::initialize_circuit(std::vector<proxy_instance *>& proxies, const SOCKET server_socket)
{
#ifdef DEBUG_OUT
	if (proxy::destination_target->ip_address != NULL) {
		D("Active chain to %s:%d: \n", proxy::destination_target->ip_address, proxy::destination_target->port);
	} else if (proxy::destination_target->domain != NULL) {
		D("Active chain to %s:%d: \n", proxy::destination_target->domain, proxy::destination_target->port);
	}
#endif
	// Construct proper destination objects
	for (UINT i = 0; i < proxies.size(); i++) {
		proxy::PDEST_INFO dest_info = (PDEST_INFO)mem::malloc(sizeof(DEST_INFO));
		if (i == (proxies.size() - 1)) {
			// Last entry must point to the target server
			//dest_info->ip_address	= new str_string(proxy::destination_target->ip_address);
			dest_info->port				= proxy::destination_target->port;
			if (proxy::destination_target->ip_address != NULL) {
				dest_info->ip_address	= new str_string(proxy::destination_target->ip_address);
			} else if (proxy::destination_target->domain != NULL) {
				// Resolve domain name to ip address string
				struct hostent *host_info;
				host_info = gethostbyname(proxy::destination_target->domain);
				struct in_addr addy;
				mem::zeromem(&addy, sizeof(struct in_addr));
				addy.S_un.S_addr		= *(u_long *)host_info->h_addr_list[0];
				PCHAR addy_string		= (PCHAR)inet_ntoa(addy);
				dest_info->ip_address = new str_string(addy_string);
			}
		} else {
			dest_info->ip_address		= new str_string(proxies.at(i + 1)->proxy_ip->to_lpstr());
			dest_info->port				= proxies.at(i + 1)->proxy_port;
		}
		proxy_instance::PROXY_CLASS_ERROR adjust_status = proxies.at(i)->adjust_dest(dest_info);
		if (adjust_status != proxy_instance::ER_OK) {
			proxy::destroy_chain(proxies);
			return INVALID_SOCKET;
		}
#ifdef DEBUG_OUT
		D("\t-> %s:%d\n", proxies.at(i)->proxy_ip->to_lpstr(), proxies.at(i)->proxy_port);
#endif
	}

	// SOCKET time
	proxy_instance::PROXY_CLASS_ERROR init_status;
	SOCKET tx_socket = INVALID_SOCKET;
	if (server_socket == INVALID_SOCKET) {
		init_status = proxies.at(0)->init_socket(&proxy::wsadata, &tx_socket);
		if (init_status != proxy_instance::ER_OK) {
			if (tx_socket != INVALID_SOCKET) {
				proxies.at(0)->close_socket();
				proxy::destroy_chain(proxies);
				return INVALID_SOCKET;
			}
		}
	} else {
		tx_socket = server_socket;
		proxies.at(0)->inherit_socket(server_socket);
	}

#if defined (USE_SOCKS5)
	proxy_instance::PROXY_CLASS_ERROR socks5_status = proxies.at(0)->init_socks5_relay(&tx_socket);
#elif defined (USE_SOCKS4)
	proxy_instance::PROXY_CLASS_ERROR socks5_status = proxies.at(0)->init_socks4_relay(&tx_socket);
#endif
	if (socks5_status != proxy_instance::ER_OK) {
		if (tx_socket != INVALID_SOCKET) {
			proxies.at(0)->close_socket();
			proxy::destroy_chain(proxies);
			return INVALID_SOCKET;
		}
	}
	for (UINT i = 1; i < proxies.size(); i++) {
		proxies.at(i)->inherit_socket(tx_socket);
#if defined (USE_SOCKS5)
		proxy_instance::PROXY_CLASS_ERROR socks5_status = proxies.at(i)->init_socks5_relay(&tx_socket);
#elif defined (USE_SOCKS4)
		proxy_instance::PROXY_CLASS_ERROR socks5_status = proxies.at(i)->init_socks4_relay(&tx_socket);
#endif
		if (socks5_status != proxy_instance::ER_OK) {
			if (tx_socket != INVALID_SOCKET) {
				proxies.at(i)->close_socket();
				proxy::destroy_chain(proxies);
				return INVALID_SOCKET;
			}
		}
	}

	return tx_socket;
}

VOID proxy::destroy_chain(std::vector<proxy_instance *>& proxies)
{
	for (UINT i = 0; i < proxies.size(); i++) {
		delete proxies.at(i);
	}

	proxies.erase(proxies.begin(), proxies.end());	

	return;
}

proxy::ER_PROXY proxy::remove_broken_proxy_from_working_servers(proxy_instance *instance, std::vector<proxy_instance *>& chain)
{
#ifdef DEBUG_OUT
	D("[!] Server %s:%d failed. Removing from working servers\n", instance->proxy_ip->to_lpstr(), instance->proxy_port);
#endif
	proxy::working_servers->sync(true);

	LPSTR raw_file_buffer;
	UINT raw_file_size;
	BOOL read_status		= fs::read_raw_into_buffer(proxy::working_servers->get_working_proxies_target_file(),
		&raw_file_size, (LPVOID *)&raw_file_buffer);
	if (!read_status) {
#ifdef DEBUG_OUT
		D("[!] Failed to remove server! Exiting.\n");
#endif
		proxy::working_servers->sync(false);
		cExitProcess(0);
	}
	raw_file_buffer = (LPSTR)mem::realloc(raw_file_buffer, raw_file_size + str::ASCII_CHAR, true);

	LPSTR port_ip_buffer	= instance->get_port_ip_string(instance->proxy_ip, instance->proxy_port);
	LPSTR new_buffer;
	UINT new_buffer_size;
	str::remove_sequence_from_buffer_realloc(raw_file_buffer, raw_file_size, 
		port_ip_buffer, str::lenA(port_ip_buffer), &new_buffer, &new_buffer_size);	

	std::vector<proxy_instance *> *functional_servers = proxy::working_servers->get_working_servers();
	for (UINT i = 0; i < functional_servers->size(); i++) {
		if (functional_servers->at(i) == instance) {
			// Remove server
			delete functional_servers->at(i);
			functional_servers->erase(functional_servers->begin() + i);
			break;
		}
	}

	cDeleteFileA(proxy::working_servers->get_working_proxies_target_file());
	BOOL write_status		= fs::write_raw_to_disk(proxy::working_servers->get_working_proxies_target_file(),
		(PDWORD)new_buffer, new_buffer_size - str::ASCII_CHAR);
	if (!write_status) {
#ifdef DEBUG_OUT
		D("[!] Failed to update server! Exiting.\n");
#endif
		proxy::working_servers->sync(false);
		cExitProcess(0);
	}

	// Remove from chain
	for (UINT i = 0; i < chain.size(); i++) {
		if (chain.at(i) == instance) {
			chain.erase(chain.begin() + i);
			break;
		}
	}

	mem::free(new_buffer);
	mem::free(port_ip_buffer);
	proxy::working_servers->sync(false);
	return ER_PROXY_OK;
}

// Fixes everything, but does not test the circuit again
proxy::ER_PROXY proxy::test_circuit_and_fix(std::vector<proxy_instance *>& chain)
{
	// Test each proxy in the chain
	bool removed = false;
remove: //fixme
	for (UINT i = 0; i < chain.size(); i++) {
		PDEST_INFO dest_info							= (PDEST_INFO)mem::malloc(sizeof(DEST_INFO));
		dest_info->ip_address							= (DEST_ADDRESS)new str_string(proxy::test_host);
		dest_info->port									= (DEST_PORT)proxy::test_port;
		chain.at(i)->adjust_dest(dest_info);

		SOCKET tx_socket;
		proxy_instance::PROXY_CLASS_ERROR init_status   = chain.at(i)->init_socket(&proxy::wsadata, &tx_socket);
		if (init_status != proxy_instance::ER_OK) {
			// Proxy failed
			removed = true;
			remove_broken_proxy_from_working_servers(chain.at(i), chain);
			goto remove;
		}

#if defined (USE_SOCKS5)
		proxy_instance::PROXY_CLASS_ERROR socks_status  = chain.at(i)->init_socks5_relay(&tx_socket);
#elif defined (USE_SOCKS4)
		proxy_instance::PROXY_CLASS_ERROR socks_status  = chain.at(i)->init_socks4_relay(&tx_socket);
#endif
		if (socks_status != proxy_instance::ER_OK) {
			// Proxy failed
			removed = true;
			remove_broken_proxy_from_working_servers(chain.at(i), chain);
			goto remove;
		}

		proxy_instance::PPROXY_TEST_INFO test_info		= (proxy_instance::PPROXY_TEST_INFO)mem::malloc(sizeof(proxy_instance::PROXY_TEST_INFO));
		test_info->host									= new str_string(proxy::test_host);
		test_info->rx_string							= new str_string(proxy::test_look_for);
		test_info->port									= proxy::test_port;
		proxy_instance::PROXY_TEST_STATUS test_status	= chain.at(i)->test_connection(test_info);
		delete test_info->host;
		delete test_info->rx_string;
		mem::free(test_info);
		if (test_status != proxy_instance::TEST_OK) {
			// Proxy failed
			removed = true;
			remove_broken_proxy_from_working_servers(chain.at(i), chain);
			goto remove;
		}
	}

	chain.erase(chain.begin(), chain.end());

	if (removed == false) {
		return ER_DESTINATION_CONNECT;
	}

	return ER_PROXY_OK;
}

bool proxy::is_server_in_circuit(const proxy_instance *instance, const std::vector<std::vector<proxy_instance *>> circuits)
{
	for (UINT i = 0; i < circuits.size(); i++) {
		for (UINT c = 0; c < circuits.at(i).size(); c++) {
			if (circuits.at(i).at(c) == instance) {
				return true;
			}
		}
	}

	return false;
}

// Socks5 Server Functions ////////////////////////////////////////////////////
proxy::PR_THREAD_ENTRY socks_server::instance_handler(__in const PSOCKET rx_socket)
{
#ifdef DEBUG_OUT
	D("[+] Accepting connection.\n");
#endif
	LPVOID buffer;
	UINT buffer_size;
	proxy_instance::PROXY_WAIT_ERROR wait_status = proxy_instance::wait_and_read(*rx_socket, &buffer, &buffer_size);
	if (wait_status != proxy_instance::WAIT_RECEIVED) {
#ifdef DEBUG_OUT
		D("[+] RX Failure. Closing channel.\n");
#endif
		closesocket(*rx_socket);
		return;
	}
	if (mem::compare(proxy::socks5_greeting, buffer, sizeof(proxy::socks5_greeting))) {
#ifdef DEBUG_OUT
		D("[+] Incorrect greeting. Closing channel.\n");
#endif
		closesocket(*rx_socket);
		mem::free(buffer);
		return;
	}
	mem::free(buffer);
	proxy::socks5_greeting_response greeting_response;
	mem::zeromem(&greeting_response, sizeof(proxy::socks5_greeting_response));
	greeting_response.version = proxy::socks5_version;
	INT response_status = send(*rx_socket, (const char *)&greeting_response, sizeof(proxy::socks5_greeting_response), 0);
	if (response_status != sizeof(proxy::socks5_greeting_response)) {
#ifdef DEBUG_OUT
		D("[!] Error in transmitting.\n");
#endif
		closesocket(*rx_socket);
		mem::free(buffer);
		return;
	}
	wait_status = proxy_instance::wait_and_read(*rx_socket, &buffer, &buffer_size);
	if (wait_status != proxy_instance::WAIT_RECEIVED) {
#ifdef DEBUG_OUT
		D("[+] RX Failure. Closing channel.\n");
#endif
		closesocket(*rx_socket);
		mem::free(buffer);
		return;
	}
	proxy::socks5_client_connection_request_domain *domain_response;
	domain_response = (proxy::socks5_client_connection_request_domain *)buffer;
	if (	domain_response->version != proxy::socks5_version ||
			domain_response->command_code != proxy::socks5_command_code) {
#ifdef DEBUG_OUT
		D("[+] RX Failure. Closing channel.\n");
#endif
		closesocket(*rx_socket);
		mem::free(buffer);
		return;
	}
	proxy::TARGET_SERVER target_server;
	mem::zeromem(&target_server, sizeof(proxy::TARGET_SERVER));
	if (domain_response->address_type == proxy::socks5_address_type_ip) {
		// IP
		in_addr address_struct;
		mem::zeromem(&address_struct, sizeof(in_addr));
		address_struct.S_un.S_addr = (DWORD)&(((proxy::socks5_client_connection_request *)buffer)->ip);
		target_server.ip_address = inet_ntoa((in_addr)address_struct);
		target_server.port = htons((WORD)&(((proxy::socks5_client_connection_request *)buffer)->port));
	} else if (domain_response->address_type == proxy::socks5_address_type_dom) {
		// Domain
		LPSTR domain_name = (LPSTR)mem::malloc(domain_response->name_length + str::ASCII_CHAR);
		mem::copy(domain_name, (LPCVOID)((DWORD_PTR)buffer + sizeof(proxy::socks5_client_connection_request_domain)),
			domain_response->name_length);
		if (ip_tools::is_ip(domain_name) == true) {
			// IP
			target_server.ip_address= (LPSTR)mem::malloc(domain_response->name_length + str::ASCII_CHAR);
			mem::copy(target_server.ip_address, domain_name, domain_response->name_length);
			mem::free(domain_name);
		} else {
			// Domain
			target_server.domain	= domain_name;
		}
		target_server.port		= htons(*(PWORD)((DWORD_PTR)buffer + sizeof(proxy::socks5_client_connection_request_domain) +
			domain_response->name_length));
	}	

	// Send back response
	domain_response->command_code = proxy::socks5_auth_method;
	response_status = send(*rx_socket, (const char *)buffer, buffer_size, 0);
	if (response_status != buffer_size) {
#ifdef DEBUG_OUT
		D("[!] Error in transmission.\n");
#endif
		mem::free(buffer);
		return;
	}

#ifndef SERVER_ONLY_MODE
	SOCKET proxy_socket = proxy::build_chain(proxy::socks5_listener->get_proxy_list(), &target_server, INVALID_SOCKET);
	if (proxy_socket == INVALID_SOCKET) {
#ifdef DEBUG_OUT
		D("[!] Failed to build circuit.\n");
#endif
		mem::free(buffer);
		return;
	}

	socket_tools::socket_bind *active_socket = socket_tools::bind_sockets(*rx_socket, proxy_socket, 
		(VOID (__cdecl *)(__in const SOCKET *, __in const SOCKET *))&proxy::bound_error_callback);
	if (active_socket == NULL) {
#ifdef DEBUG_OUT
		D("[!] Failed to bind sockets!\n");
#endif
		mem::free(buffer);
	}

	cSleep(INFINITE);
	mem::free(buffer);
	return;
#else

#ifdef DEBUG_OUT
	if (target_server.domain != NULL) {
		D("[+] Started server. Connecting to %s\n", target_server.domain);
	} else if (target_server.ip_address != NULL) {
		D("[+] Started server. Connecting to %s\n", target_server.ip_address);
	}
#endif

	// Connect to socket

	cSleep(INFINITE);
	mem::free(buffer);
	return;
#endif
}

proxy::PR_THREAD_ENTRY __declspec(noreturn) socks_server::listener(__in const PSOCKET rx_socket)
{
	struct sockaddr_in addr;
	mem::zeromem(&addr, sizeof(struct sockaddr_in));
	SOCKET bind_socket = INVALID_SOCKET;
	const UINT struct_size = sizeof(struct sockaddr_in);
	while (TRUE) {
		mem::zeromem(&addr, sizeof(struct sockaddr_in));
		ERROR_CODE listen_status = listen(*rx_socket, SOMAXCONN);
		if (listen_status == SOCKET_ERROR) {
#ifdef DEBUG_OUT
			D("[!] SOCKS5 Server Failed. Exiting.\n");
#endif
			cExitProcess(0);
		}
		bind_socket = accept(*rx_socket, NULL, NULL);
		if (bind_socket == INVALID_SOCKET) {
			cSleep(10);
			continue;
		}
		cCreateThread(	NULL,
						0,
						(LPTHREAD_START_ROUTINE)instance_handler,
						(LPVOID)&bind_socket,
						0,
						NULL);
#ifdef DEBUG_OUT_
		D("[+] Listener sleeping...\n");
#endif
		//cSleep(INFINITE);
	}
}

// Wraps start_socks5_listener
proxy::socks_server *proxy::start_socks5_listener_return_object(WORD port)
{



	return NULL;
}

// This function dispatches a thread which handles all requests, returns a successs
proxy::SERVER_ERROR __declspec(dllexport) proxy::start_socks5_listener(proxy::PPROXY_LIST list, WORD port)
{
#ifndef SERVER_ONLY_MODE
	if (list == NULL || port == 0) return proxy::SERVER_ERROR_GENERAL_FAILURE;
#else 
	if (port == 0) return proxy::SERVER_ERROR_GENERAL_FAILURE;
#endif
#ifdef DEBUG_OUT
	D("[+] Starting SOCKS5 listener on %d\n", port);
#endif

	proxy::wsadata = (WSADATA *)mem::malloc(sizeof(WSADATA));
	ERROR_CODE wsa_status	= WSAStartup(MAKEWORD(2,2), proxy::wsadata);
	if (wsa_status) {
#ifdef DEBUG_OUT
		D("[!] Failed to initialize WSA\n");
#endif
		return proxy::SERVER_ERROR_GENERAL_FAILURE;
	}
	SOCKET rx_socket;
	rx_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (rx_socket == INVALID_SOCKET) {
#ifdef DEBUG_OUT

#endif
		WSACleanup();
		return proxy::SERVER_ERROR_SOCKET_INIT;
	}

	const CHAR opt_data = 1;
	ERROR_CODE opt_status	= setsockopt(rx_socket, SOL_SOCKET, SO_REUSEADDR, &opt_data, sizeof(opt_data));
	opt_status				= setsockopt(rx_socket, SOL_SOCKET, SO_KEEPALIVE, &opt_data, sizeof(opt_data));
	if (opt_status) {
#ifdef DEBUG_OUT
		D("[!] Failed to set socket options on 0x%08x", rx_socket);
#endif
		return proxy::SERVER_ERROR_SOCKOPT;
	}

	struct sockaddr_in server_addr;
	mem::zeromem(&server_addr, sizeof(sockaddr_in));
	server_addr.sin_family				= AF_INET;
	server_addr.sin_port				= htons(port);
	server_addr.sin_addr.S_un.S_addr	= INADDR_ANY;
	ERROR_CODE bind_status = bind(rx_socket, (const sockaddr *)&server_addr, sizeof(sockaddr_in));
	if (bind_status == -1) {
#ifdef DEBUG_OUT
		D("[!] Failed to bind port %d", port);
#endif
		return proxy::SERVER_ERROR_BIND;
	}

	proxy::socks5_listener = new socks_server(list, port, rx_socket);

	return proxy::SERVER_ERROR_OK;
}

// Callback function that is handled once an error occurs in the binding between the socks5 server, and the active chain
proxy::PROXY_CALLBACK proxy::bound_error_callback(__in const PSOCKET listener, __in const PSOCKET chain)
{
#ifdef DEBUG_OUT
	D("[!] Error occurred in listener->chain circuit.\n");
#endif
	return;
}

// Destroy chain, close handle, etc
VOID proxy::close_chain(const SOCKET socket)
{
	cEnterCriticalSection(proxy::sync_chain_mod);

	for (UINT i = 0; i < proxy::chain_array.size(); i++) {
		if (proxy::chain_array.at(i).front()->get_socket() == socket) {
#ifdef DEBUG_OUT
			D("[+] Removing chain. Handle 0x%08x. Destination %s:%d\n", socket, proxy::chain_array.at(i).back()->dest_ip->to_lpstr(),
				proxy::chain_array.at(i).back()->dest_port);
#endif
			proxy::chain_array.at(i).back()->close_socket();
			for (UINT c = 0; c < proxy::chain_array.at(i).size(); c++) {
				proxy::chain_array.at(i).at(c)->inherit_socket(INVALID_SOCKET);
			}
			proxy::chain_array.at(i).erase(proxy::chain_array.at(i).begin(), proxy::chain_array.at(i).end());
			proxy::chain_array.erase(proxy::chain_array.begin() + i);
			cLeaveCriticalSection(proxy::sync_chain_mod);
			return;
		}
	}

	cLeaveCriticalSection(proxy::sync_chain_mod);
	return;
}

// Build chain function - handles the main proxychain 
SOCKET __declspec(dllexport) proxy::build_chain(__in const PPROXY_LIST list, __in const PTARGET_SERVER target, 
	__in const SOCKET server_socket)
{
	if (proxy::engine_state == false) {

#ifdef DEBUG_OUT
		D("[proxychains]\n\nConfigured with:\n");

#if defined(USE_SOCKS5)
		D("-> SOCKS5 Enabled\n");
#elif defined(USE_SOCKS4)
		D("-> SOCKS4 Enabled\n");
#else

#endif
#endif

#ifdef WIN64
		D("-> %d Thread Concurrency\n", NUMBER_OF_SCANNING_THREADS);
#endif

#ifdef SCAN_MODE
#ifdef DEBUG_OUT
		DBGOUT("-> Scanning mode. Halting after 1 iteration\n-> Max Threads: %d\n-> Chain: %d\n", NUMBER_OF_SCANNING_THREADS, 
			list->number_of_chains);
#endif
#endif

#ifdef DEBUG_OUT
		D("-> Timings: TTP: %dms, TCST: %dms\n", proxy::timing_test_proxy, proxy::timing_test_proxy);
		D("-> Maximum latency: %d second(s), %d millisecond(s)\n", proxy::timeout_s_, proxy::timeout_ms_);
#endif

#ifdef WIN64
		D("-> x64 Compiled.\n");
#endif

		cSleep(1000);

		proxy::sync_chain_mod = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
		cInitializeCriticalSection(proxy::sync_chain_mod);

		if (list->buffer == NULL) {
#ifdef DEBUG_OUT
			D("[!] Working proxies file not specified. Exiting\n");
#endif
			return INVALID_SOCKET;
		}

		if (list == NULL || target == NULL) return INVALID_SOCKET;

		proxy::working_proxies_list = (proxy::PWORKING_PROXIES)mem::malloc(sizeof(WORKING_PROXIES));
		proxy::working_proxies_list->target_file = list->known_target;
		proxy::engine_state = true;
		if (list->known_target != NULL) {
#ifdef DEBUG_OUT_
			D("[+] Working proxy list specified.\n");
#endif
			LPVOID buffer;
			UINT buffer_size;
			BOOL read_status = fs::read_raw_into_buffer(list->known_target, &buffer_size, &buffer);
			if (read_status == FALSE) {
#ifdef DEBUG_OUT
				D("[!] Failed to read working proxy file, creating new file: %s\n", list->known_target);
#endif
			} else {
				working_proxies_list->size		= buffer_size;
				working_proxies_list->buffer	= (LPVOID)mem::malloc(buffer_size + str::ASCII_CHAR);
				mem::copy(working_proxies_list->buffer, buffer, buffer_size);
#ifdef DEBUG_OUT
				D("[+] Working proxies file read\n");
#endif
			}
		}

#ifdef DEBUG_OUT
		D("[+] Loading data...\n");
#endif

		// Parse input file; create scanner object
		// Parse input
		str_string *input_list = new str_string(str_string::MODE_SPLIT_LINE, (LPCSTR)list->buffer, list->size);
		std::vector<PPROXY_ENTRY> entries;
		str::PLINE current_line = input_list->get_first_line();
		while (current_line != NULL) {


			PPROXY_ENTRY chain	= (PPROXY_ENTRY)mem::malloc(sizeof(PROXY_ENTRY));
			chain->buffer		= (PROXY_ADDRESS)new str_string(current_line->line_buffer);
			entries.push_back(chain);

			current_line = current_line->next_line;
		}

#ifdef DEBUG_OUT
		D("[+] Parsing...\n");
#endif

		// Parse IP:Port
		for (UINT i = 0; i < entries.size(); i++) {
			std::vector<LPSTR> tmp		= entries.at(i)->buffer->split_string_by_terminatorA(NULL, ":", str::lenA(":"));
			if (tmp.size() != 2) { 
				mem::free(entries.at(i));
				entries.erase(entries.begin() + i);
				i--;
				continue;
			}
			entries.at(i)->ip_address	= (PROXY_ADDRESS)new str_string((LPSTR)tmp.at(0));
			entries.at(i)->port			= (PROXY_PORT)atoi((const char *)tmp.at(1)); // Network byte order is done later

#ifdef DEBUG_OUT_
			D("[+] Loaded server from config: %s:%d\n", entries.at(i)->ip_address->to_lpstr(), entries.at(i)->port);
#endif
		}

#ifdef DEBUG_OUT
		D("[+] %d ports open\n", entries.size());
#endif

		// Create thread for computing functional_server_list, wait 
		proxy::working_servers = new functional_servers(entries, working_proxies_list);

#ifdef SCAN_MODE
#ifdef DEBUG_OUT
		D("[+] Scanning...\n");
#endif
		cSleep(INFINITE);
#endif

#ifdef DEBUG_OUT
		D("[+] Waiting for %d servers to become available...\n", list->number_of_chains);
#endif
		while (proxy::working_servers->get_working_servers()->size() < list->number_of_chains) Sleep(500);

#ifdef DEBUG_OUT
		D("[+] We have a minimum amount of proxies available.\n");
#endif
	} else {
#ifdef DEBUG_OUT
		D("[+] Building new circuit...\n");
#endif
	}

	while (((proxy::chain_array.size() * list->number_of_chains) + list->number_of_chains) > 
		proxy::working_servers->get_working_servers()->size()) {
#ifdef DEBUG_OUT
		D("[+] Waiting on a server...\n");
#endif
		cSleep(5000);
	}

	/* Freeing proxy::destination_target is up to the caller, not build_chains. This means that the SOCKS5 server must too
	cleanup after use
	if (proxy::destination_target != NULL) {
		if (destination_target->domain != NULL) mem::free(destination_target->domain);
		if (destination_target->ip_address != NULL) mem::free(destination_target->ip_address);
		mem::free(proxy::destination_target);
	}*/
	proxy::destination_target = target;

	// Build circuit
	SOCKET tx_socket;
	cEnterCriticalSection(proxy::sync_chain_mod);
	while (TRUE) {
		std::vector<proxy_instance *> new_chain;
		for (UINT i = 0; i < list->number_of_chains; i++ ) {
			if (proxy::functional_server_counter >= proxy::working_servers->get_working_servers()->size()) {
				proxy::functional_server_counter = 0;
			}
			if (proxy::is_server_in_circuit(proxy::working_servers->get_working_servers()->at(proxy::functional_server_counter),
				proxy::chain_array) == true) {
				proxy::functional_server_counter = proxy::functional_server_counter + 1;

				continue;
			}
			new_chain.push_back(proxy::working_servers->get_working_servers()->at(proxy::functional_server_counter));
			proxy::functional_server_counter = proxy::functional_server_counter + 1;
		}
		tx_socket = proxy::initialize_circuit(new_chain, server_socket);
		if (tx_socket == INVALID_SOCKET) {
#ifdef DEBUG_OUT
			printf("[!] Failed to build chain! All servers are functional. Trying again...\n");
#endif
			proxy::ER_PROXY proxy_status = proxy::test_circuit_and_fix(new_chain);
			if (proxy_status == proxy::ER_DESTINATION_CONNECT) {
#ifdef DEBUG_OUT
				printf("[!] Destination server failed to respond.\n");
#endif
				cLeaveCriticalSection(proxy::sync_chain_mod);
				return INVALID_SOCKET;
			}

			while (proxy::working_servers->get_working_servers()->size() < list->number_of_chains) cSleep(500);

			continue;
		} else {
#ifdef DEBUG_OUT
			printf("[!] Chain built! SOCKET: 0x%08x\n", tx_socket);
#endif
			proxy::chain_array.push_back(new_chain);
			cLeaveCriticalSection(proxy::sync_chain_mod);
			return tx_socket;
		}
	}

	// Not called
	cLeaveCriticalSection(proxy::sync_chain_mod);
	return INVALID_SOCKET;
}

#undef DBG

#ifdef SERVER_ONLY_MODE
SOCKET proxy::connect_to_socks5_server(__in const LPSTR server_address, __in const WORD server_port,
	__in const LPSTR dest_address, __in const WORD dest_port)
{
	PROXY_INFO server_info;
	mem::zeromem(&server_info, sizeof(PROXY_INFO));
	server_info.ip_address = new str_string(server_address);
	server_info.port = server_port;
	DEST_INFO dest_info;
	mem::zeromem(&dest_info, sizeof(DEST_INFO));
	dest_info.domain = new str_string(dest_address);
	dest_info.port = dest_port;
	
	proxy_instance *instance = new proxy_instance(&server_info, &dest_info);
	
	SOCKET tx_socket = INVALID_SOCKET;
	proxy_instance::PROXY_CLASS_ERROR connect_status = instance->init_socket(NULL, &tx_socket);
	if (connect_status != proxy_instance::ER_OK) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Timeout connecting to %s:%d\n", server_address, server_port);
#endif
		return INVALID_SOCKET;
	}

	connect_status = instance->init_socks5_relay(&tx_socket);
	if (connect_status != proxy_instance::ER_OK) {
		return INVALID_SOCKET;
	}

	return tx_socket;
}
#endif