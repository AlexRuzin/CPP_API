#define _WINSOCKAPI_

#include <WinSock2.h>

#include <Windows.h>
#include <vector>

#include "socket_lib.h"

#include "../../_api/common/mem.h"
#include "../../_api/common/str.h"
#include "../../_api/api.h"

#pragma comment (lib, "ws2_32.lib")

using namespace socket_tools;

socket_tools::SOCKET_THREAD_ENTRY __st_thread_conv socket_data::wait_thread(__in const __this_ptr This)
{
	socket_tools::data *new_data;
	while (TRUE) {
		LPVOID buffer;
		UINT buffer_size;
		socket_tools::ER_WAIT_AND_READ wait_status = socket_tools::wait_and_read(
			This->get_socket(), socket_tools::_timeout_s, socket_tools::_timeout_ms, &buffer, &buffer_size);
		switch (wait_status) 
		{
		case ER_WAIT_OK:
			new_data = new socket_tools::data(buffer, buffer_size, This->get_socket(), INVALID_SOCKET);
			This->handler(new_data, This);
			return;
		case ER_WAIT_FAIL:
			break;
		case ER_WAIT_NOTHING_RECEIVED:
			break;
		case ER_WAIT_TIMEOUT:
			continue;
		default:
			break;
		}
	}

	// Close socket, cleanup
	delete This;
}

socket_data::SOCKET_DATA_ERROR socket_tools::socket_data::wait_and_dispatch(
	__in const SOCKET rx_socket, __in const socket_data::f_handler handler)
{
	if (rx_socket == INVALID_SOCKET || handler == NULL) return WAIT_FAIL;

	this->handler = handler;
	this->wait_and_read_thread = socket_tools::start_thread((LPTHREAD_START_ROUTINE)wait_thread, this);
	if (this->wait_and_read_thread == NULL) return WAIT_FAIL;

	return WAIT_OK;
}

socket_data::socket_data(__in PINIT_SOCKET_DATA init_data_param)
{
	if (init_data_param == NULL) return;
	this->init_data = (PINIT_SOCKET_DATA)init_data_param;

	socket_handle			= INVALID_SOCKET;
	wait_and_read_thread	= INVALID_HANDLE_VALUE;
	ip						= NULL;
	domain					= NULL;
	port					= init_data_param->port;

	if (init_data_param->type == server_type::TYPE_IP) {
		this->ip = init_data_param->ip;
	} else if (init_data_param->type == server_type::TYPE_DOMAIN) {
		struct hostent *host_info = gethostbyname((const char *)init_data_param->domain->to_lpstr());
		struct in_addr address;
		mem::zeromem(&address, sizeof(struct in_addr));
		address.S_un.S_addr = *(u_long *)host_info->h_addr_list[0];
		this->ip = new str_string(inet_ntoa(address));
	} else {
		return;
	}

	if (socket_tools::init_wsastartup == true) {
		if (socket_tools::wsadata == NULL) {
			socket_tools::wsadata = (WSADATA *)mem::malloc(sizeof(WSADATA));
			ERROR_CODE wsa_status = WSAStartup(MAKEWORD(2, 2), socket_tools::wsadata);
			if (wsa_status) return;
		}
	}

	SOCKET tx_socket				= INVALID_SOCKET;
	tx_socket						= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tx_socket == INVALID_SOCKET) return;

	struct sockaddr_in address;
	mem::zeromem(&address, sizeof(struct sockaddr_in));
	address.sin_addr.S_un.S_addr	= inet_addr(this->ip->to_lpstr());
	address.sin_family				= AF_INET;
	address.sin_port				= htons(init_data_param->port);
	ST_ERROR socket_status			= connect(tx_socket, (const sockaddr *)&address, sizeof(const sockaddr));
	if (socket_status == SOCKET_ERROR) {
		return;
	}

	this->socket_handle = tx_socket;
	return;
}

class socket_tools::socket_bind {
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
	} IO_INFO, *PIO_INFO;
	PIO_INFO				info_a, info_b;
	HANDLE					thread_a;
	HANDLE					thread_b;
	static socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv socket_bind::bound_io_thread(PIO_INFO info);

	// Error handler. Cleans up and dispatches to error_handler callback
	VOID socket_bind::error_handler_local(VOID);

	// Data handler. Data is passed to this function. If it is NULL, it is bypassed.
	socket_tools::data_callback	data_handler;

public:
	// Ctors/Dtors. a is generally a client (obtained through listen), b is a server (obtained through connect).
	socket_bind(socket_data *a, socket_data *b, error_callback error_handler, data_callback data_handler) :
		a(INVALID_SOCKET),
		b(INVALID_SOCKET),
		error_handler(error_handler), data_handler(data_handler),
		lock(NULL),
		thread_a(INVALID_HANDLE_VALUE),
		thread_b(INVALID_HANDLE_VALUE),
		sa(a), sb(b),
		buffer_a(NULL), buffer_b(NULL)
	{
		if (a->get_socket() == INVALID_SOCKET || b->get_socket() == INVALID_SOCKET) return;
		this->a = sa->get_socket();
		this->b = sb->get_socket();

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
			
		this->bind_state = true;
	}
	socket_bind(SOCKET a, SOCKET b, error_callback error_handler, data_callback data_handler) :
		a(a),
		b(b),
		error_handler(error_handler), data_handler(data_handler),
		lock(NULL),
		thread_a(INVALID_HANDLE_VALUE),
		thread_b(INVALID_HANDLE_VALUE),
		sa(NULL), sb(NULL),
		buffer_a(NULL), buffer_b(NULL)
	{
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

		this->bind_state = true;
	}
	~socket_bind(VOID)
	{
		mem::free(this->lock);
		cTerminateThread(this->thread_a, 0);
		cTerminateThread(this->thread_b, 0);
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

socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv socket_tools::socket_bind::bound_io_thread(PIO_INFO info)
{
	cSleep(10);
	SOCKET listener, recipient;
	switch (info->mode)
	{
	case true: //a->b (wait and read on a)
		listener	= info->a;
		recipient	= info->b;
		//Sleep(INFINITE);
		break;
	case false:
		listener	= info->b;
		recipient	= info->a;
	}

	printf("[+] I/O BIND: listener: 0x%08x. recipient: 0x%08x\n", listener, recipient);

	while (TRUE) {
		socket_tools::data *new_data;
		LPVOID buffer;
		UINT buffer_size;
		//printf("0x%08x mode: %d\n", listener, info->mode);
		socket_tools::ER_WAIT_AND_READ wait_status = socket_tools::wait_and_read(listener, 
			socket_tools::_timeout_s, socket_tools::_timeout_ms, &buffer, &buffer_size);
		//info->This->sync(true);
		switch (wait_status)
		{
		case ER_WAIT_NOTHING_RECEIVED:
			//info->This->sync(false);
			continue;
		case ER_WAIT_OK:
			// Send data
			new_data = new socket_tools::data(buffer, buffer_size, listener, recipient);
			info->This->data_handler(new_data);
			
			//info->This->sync(false);
			continue;
		case ER_WAIT_FAIL:
			info->This->error_handler(&listener, &recipient, info->This);
			cSleep(INFINITE);
		case ER_WAIT_TIMEOUT:
			//info->This->sync(false);
			continue;
		}
	}
}

socket_tools::socket_bind *socket_tools::bind_sockets(SOCKET a, SOCKET b, socket_data *sa, socket_data *sb,
	error_callback error_handler, data_callback data_handler)
{
	if (error_handler == NULL) return NULL;

	socket_tools::socket_bind *bound_sockets = new socket_tools::socket_bind(sa, sb, error_handler, data_handler);

	return bound_sockets;
}

socket_tools::ER_WAIT_AND_READ socket_tools::wait_and_read(__in SOCKET rx_socket, 
	__in const TIME32 time_s, __in const TIME32 time_u, __inout LPVOID *buffer, __out PUINT buffer_size)
{
	if (rx_socket == INVALID_SOCKET) return ER_WAIT_FAIL;

	*buffer			= NULL;
	*buffer_size	= 0;

	struct timeval timed;
	mem::zeromem(&timed, sizeof(struct timeval));
	timed.tv_sec			= time_s;
	timed.tv_usec			= time_u;
	fd_set read_flags, write_flags;
	FD_ZERO(&read_flags);
	FD_ZERO(&write_flags);
	FD_SET(0, &write_flags);
	FD_SET(rx_socket, &read_flags);

	BYTE rx_buffer[recv_buf_size];
	while (TRUE) {

	}


	/*
	PUCHAR rx_buffer		= (PUCHAR)mem::malloc(str::ASCII_CHAR);
	UINT rx_buffer_length	= str::ASCII_CHAR;
	while (TRUE) {
		mem::zeromem(rx_buffer_new, recv_buf_size);

		INT select_status = select(rx_socket, &read_flags, NULL, NULL, &timed);
		if (!select_status) {
			if (select_status == SOCKET_ERROR) {
				mem::free(rx_buffer);
				return ER_WAIT_FAIL;
			} else if (read_flags.fd_count == 0) {
				if (rx_buffer_length == str::ASCII_CHAR) {
					mem::free(rx_buffer);
					return ER_WAIT_TIMEOUT;
				}
				break;
			}
			break;
		}

		UCHAR byte	= 0;
		UINT rxd	= recv(rx_socket, (char *)&byte, sizeof(UCHAR), 0);
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
		return ER_WAIT_NOTHING_RECEIVED;
	}

	*buffer			= rx_buffer;
	*buffer_size	= rx_buffer_length;

	return ER_WAIT_OK;*/
}

HANDLE socket_tools::start_thread(__in const LPTHREAD_START_ROUTINE oep, __in const LPVOID parameter)
{
	if (oep == NULL) return INVALID_HANDLE_VALUE;

	HANDLE thread_handle = cCreateThread(	NULL,
											0,
											oep,
											parameter,
											0,
											NULL);
	return thread_handle;
}
