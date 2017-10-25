//#include "external/ssl.h"

#include <vector>


#include "api.h"
#include "common/mem.h"
#include "common/str.h"
#include "crypt/crypt.h"

#include "socket.h"

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "Secur32.lib")

using namespace socket_tools;

socket_tools::SOCKET_THREAD_ENTRY __st_thread_conv socket_data::wait_thread(__in const __this_ptr This)
{
	socket_tools::data *new_data;
	while (TRUE) {
		LPVOID buffer;
		UINT buffer_size;
		socket_tools::ER_WAIT_AND_READ wait_status = socket_tools::wait_and_read(
			This->get_socket(), This->_timing_initial_request_s, This->_timing_initial_request_ms, &buffer, &buffer_size);
		if (wait_status == ER_WAIT_OK) {
			printf("[+] size of initial request: %d\n", buffer_size);
			new_data = new socket_tools::data(buffer, buffer_size, This->get_socket(), INVALID_SOCKET);
			This->handler(new_data, This);
			cSleep(INFINITE);
		} else {
			break;
		}
	}

	// Close socket, cleanup
	printf("[!] GET timeout\n");
	cSleep(INFINITE);
}

socket_data::SOCKET_DATA_ERROR socket_tools::socket_data::wait_and_dispatch(
	__in const SOCKET rx_socket, __in const socket_data::f_handler handler, 
	__in const types::TIME32 _timing_initial_get_request_timeout_s, 
	__in const types::TIME32 _timing_initial_get_request_timeout_ms)
{
	if (rx_socket == INVALID_SOCKET || handler == NULL) return WAIT_FAIL;

	this->_timing_initial_request_s		= _timing_initial_get_request_timeout_s;
	this->_timing_initial_request_ms	= _timing_initial_get_request_timeout_ms;
	this->handler = handler;
	this->wait_and_read_thread = socket_tools::start_thread((LPTHREAD_START_ROUTINE)wait_thread, this);
	if (this->wait_and_read_thread == NULL) {
		printf("[!] Failed to start wait_thread\n");
		return WAIT_FAIL;
	}

	return WAIT_OK;
}

socket_data::socket_data(__in PINIT_SOCKET_DATA init_data_param)
{
#ifdef USE_SOCKET_ENCRYPTION
	this->EncryptedChannel = NULL;
#endif			 

	if (init_data_param == NULL) return;
	this->init_data = new init_socket_data();
	mem::copy(this->init_data, init_data_param, sizeof(INIT_SOCKET_DATA));

	if (init_data_param->domain != NULL) {
		this->init_data->domain = new str_string(init_data_param->domain->to_lpstr());
	} else if (init_data_param->ip != NULL) {
		this->init_data->ip = new str_string(init_data_param->ip->to_lpstr());
	} else {
		mem::free_and_null((LPVOID *)&this->init_data);
		return;
	}

	this->is_connected		= false;
	this->WaitData			= NULL;

	socket_handle			= INVALID_SOCKET;
	wait_and_read_thread	= INVALID_HANDLE_VALUE;
	IP						= NULL;
	port					= init_data_param->port;
	is_data_available		= FALSE;

	_timing_initial_request_ms	= socket_data::default_zero_time;
	_timing_initial_request_s	= socket_data::default_zero_time;

	if (socket_tools::init_wsastartup == true) {
		if (socket_tools::wsadata == NULL) {
			socket_tools::wsadata = (WSADATA *)mem::malloc(sizeof(WSADATA));
			ERROR_CODE wsa_status = WSAStartup(MAKEWORD(2, 2), socket_tools::wsadata);
			if (wsa_status) return;
		}
	}

	if (init_data_param->type == TYPE_IP) {
		this->IP = this->init_data->ip;
	} else if (init_data_param->type == TYPE_DOMAIN) {
		struct hostent *host_info = NULL;

		if (init_data_param->gethostbyname_timeout_iterations == 0) {
			while (host_info == NULL) {
				host_info = gethostbyname((const char *)init_data_param->domain->to_lpstr());
				if (host_info != NULL) break;
				printf("[!] Retrying gethostbyname(%s)\n", init_data_param->domain->to_lpstr());
				cSleep(TIMEOUT_GETHOSTBYNAME_RETRY);
			}
		} else {
			UINT i;
			for (i = 0; i < init_data_param->gethostbyname_timeout_iterations; i++) {
				host_info = gethostbyname((const char *)init_data_param->domain->to_lpstr());
				if (host_info == NULL) {
					D("[!] Retrying gethostbyname(%s). Retry %d of %d\n", init_data_param->domain->to_lpstr(),
						i, init_data_param->gethostbyname_timeout_iterations);
					cSleep(TIMEOUT_GETHOSTBYNAME_RETRY);
					continue;
				}

				break;
			}

			if (i == init_data_param->gethostbyname_timeout_iterations) {
				D("[!] Failed to resolve domain name\n");
				return;
			}
		}

		struct in_addr address;
		mem::zeromem(&address, sizeof(struct in_addr));
		address.S_un.S_addr = *(u_long *)host_info->h_addr_list[0];
		this->IP = new str_string(inet_ntoa(address));
	} else {
		return;
	}

	SOCKET tx_socket				= INVALID_SOCKET;
	tx_socket						= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tx_socket == INVALID_SOCKET) return;

	struct sockaddr_in address;
	mem::zeromem(&address, sizeof(struct sockaddr_in));
	address.sin_addr.S_un.S_addr	= inet_addr(this->IP->to_lpstr());
	address.sin_family				= AF_INET;
	address.sin_port				= htons(init_data_param->port);
	ST_ERROR socket_status			= connect(tx_socket, (const sockaddr *)&address, sizeof(const sockaddr));
	if (socket_status == SOCKET_ERROR) {
		return;
	}

	this->socket_handle = tx_socket;
	this->is_connected	= true;
	return;
}

VOID __declspec(noreturn) socket_tools::socket_bind::default_error_handler(__in const PIO_INFO info)
{
	printf("[!] Error handler...\n");
	cSetEvent(info->This->default_sync);
	cSleep(INFINITE);
}

VOID __declspec(noreturn) socket_tools::socket_bind::default_data_handler(__in const PIO_INFO info,
	__in socket_tools::data *data_buffer)
{
	LPVOID buffer;
	UINT buffer_size;
	data_buffer->get_buffer(&buffer, &buffer_size);

#ifdef DEBUG_OUT
	LPSTR debug_out = (LPSTR)mem::malloc(buffer_size + str::ASCII_CHAR);
	mem::copy(debug_out, buffer, buffer_size);
	if (str::is_charA(debug_out, buffer_size) == true) {
		DBGOUT("io: %s\n", debug_out);
	}
	mem::free(debug_out);
#endif

	INT send_status = send(data_buffer->get_socket(socket_tools::data::TYPE_DESINATION), 
		(const char *)buffer, buffer_size, 0);
	if (send_status != buffer_size) {
		default_error_handler(info);
	}
}

socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv
	socket_tools::socket_bind::io_thread(__in const PIO_INFO info)
{
		UINT			io_total = 0;
		bool			socket_a = false, socket_b = false;

		// Init event
		if (info->This->error_handler == NULL && info->This->data_handler == NULL) {
			info->This->default_sync = CreateEvent(NULL, TRUE, FALSE, NULL);
		}

	while (TRUE) {
		PBYTE			tmp_buffer = NULL;

		fd_set			readfds;
		struct timeval	timing;

		FD_ZERO(&readfds);
		FD_SET(info->a, &readfds);
		FD_SET(info->b, &readfds);
		timing.tv_sec	= info->_io_thread_select_timeout_s;
		timing.tv_usec	= info->_io_thread_select_timeout_ms;

		INT select_status = select((info->a > info->b) ? info->a + 1 : info->b + 1, &readfds, NULL, NULL, &timing);
		if (select_status == SOCKET_ERROR) {
			if (info->This->error_handler != NULL) {
				info->This->error_handler(&info->a, &info->b, info->This);
			} else {
				info->This->default_error_handler(info);
			}
			//ExitThread(0);
		} else if (select_status == 0) {
			mem::free(tmp_buffer);
			printf("[+] Timeout (%ds:%dms). %d:%d (io: %d)\n", info->_io_thread_select_timeout_s,
				info->_io_thread_select_timeout_ms, info->a, info->b, io_total);
			if (info->This->error_handler != NULL) {
				info->This->error_handler(&info->a, &info->b, info->This);
			} else {
				info->This->default_error_handler(info);
			}
			//ExitThread(0);
		}

		// Data available
		if (FD_ISSET(info->a, &readfds)) {
			tmp_buffer = (PBYTE)mem::malloc(recv_buf_size);
			if (tmp_buffer == NULL) {
				printf("[+] Memory allocation failure.\n");
				cExitProcess(0);
			}
			INT read_status = recv(info->a, (char *)tmp_buffer, recv_buf_size, 0);
			if (read_status == 0) {
				// Gracefully closed
				mem::free(tmp_buffer);
				printf("[+] Closed gracefully. %d:%d (io: %d) (a->b) [Request!]\n", info->a, info->b, io_total);
				if (info->This->error_handler != NULL) {
					info->This->error_handler(&info->a, &info->b, info->This);
				} else {
				info->This->default_error_handler(info);
			}
				//ExitThread(0);
			} else if (read_status == SOCKET_ERROR) {
				// Error
				mem::free(tmp_buffer);
				printf("[+] Socket Error. %d:%d (io: %d) (a->b) [Request!]\n", info->a, info->b, io_total);
				if (info->This->error_handler != NULL) {
					info->This->error_handler(&info->a, &info->b, info->This);
				} else {
				info->This->default_error_handler(info);
			}
				//ExitThread(0);
			}

			// Send data
			//printf("[+] Request(%d): %s", info->a, tmp_buffer);
			io_total += read_status;
			socket_tools::data *new_data = new socket_tools::data(tmp_buffer, read_status, info->a, info->b);
			if (info->This->data_handler != NULL) {
				info->This->data_handler(new_data);
			} else {
				info->This->default_data_handler(info, new_data);
			}
			delete new_data;
			//FD_CLR(info->a, &readfds);
		}

		if (FD_ISSET(info->b, &readfds)) {
			while (TRUE) {
				tmp_buffer = (PBYTE)mem::malloc(recv_buf_size);
				if (tmp_buffer == NULL) {
					printf("[+] Memory allocation failure.\n");
					cExitProcess(0);
				}
				INT read_status = recv(info->b, (char *)tmp_buffer, recv_buf_size, 0);
				if (read_status == 0) {
					// Gracefully closed
					mem::free(tmp_buffer);
					printf("[+] Closed gracefully. %d:%d (io: %d) (b->a)\n", info->b, info->a, io_total);
					if (info->This->error_handler != NULL) {
						info->This->error_handler(&info->a, &info->b, info->This);
					} else {
						info->This->default_error_handler(info);
					}
					//ExitThread(0);
				} else if (read_status == SOCKET_ERROR) {
					// Error
					mem::free(tmp_buffer);
					printf("[+] Socket Error. %d:%d (io: %d) (b->a)\n", info->b, info->a, io_total);
					if (info->This->error_handler != NULL) {
						info->This->error_handler(&info->a, &info->b, info->This);
					} else {
						info->This->default_error_handler(info);
					}
					//ExitThread(0);
				}

				// Send data
				//printf("(b->a) %d\n", read_status);
				io_total += read_status;
				socket_tools::data *new_data = new socket_tools::data(tmp_buffer, read_status, info->b, info->a);
				if (info->This->data_handler != NULL) {
					info->This->data_handler(new_data);
				} else {
					info->This->default_data_handler(info, new_data);
				}
				FD_CLR(info->b, &readfds);
				delete new_data;

				FD_ZERO(&readfds);
				FD_SET(info->a, &readfds);
				FD_SET(info->b, &readfds);
				timing.tv_sec	= info->_io_thread_select_timeout_s;
				timing.tv_usec	= info->_io_thread_select_timeout_ms;
				INT select_status = select(info->b, &readfds, NULL, NULL, &timing);
				if (!FD_ISSET(info->b, &readfds)) {
					break;
				}
			}
		}
	}
}

/*
socket_bind::BIND_THREAD __declspec(noreturn) __st_thread_conv 
	socket_tools::socket_bind::io_thread(__in const PIO_INFO info)
{
	//printf("[+] I/O BIND: 0x%08x, 0x%08x\n", info->a, info->b);

	fd_set readfds;
	struct timeval timing;
	UINT timeout_iterations = 0;
	while (timeout_iterations < socket_tools::_timeout_iter) {
		FD_ZERO(&readfds);
		FD_SET(info->a, &readfds);
		FD_SET(info->b, &readfds);
		timing.tv_sec = _timeout_s_io;
		timing.tv_usec = _timeout_ms_io;
		INT select_status = select((info->a > info->b) ? info->a + 1 : info->b + 1, &readfds, NULL, NULL, &timing);
		if (select_status == -1) {
			info->This->error_handler(&info->a, &info->b, info->This);
		} else if (select_status == ER_WAIT_TIMEOUT) {
			info->This->error_handler(&info->a, &info->b, info->This);
		} else if (select_status == 0) {
			// Nothing to read
			cSleep(10);
			FD_CLR(info->a, &readfds);
			FD_CLR(info->b, &readfds);
			timeout_iterations++;
			continue;
		} else {
			if (FD_ISSET(info->a, &readfds)) {
				// client->server (a->b)
				PBYTE total_buffer = NULL;
				UINT total_rx = 0;
				while (TRUE) {
					BYTE tmp_buffer[recv_buf_size] = {0};
					INT read_status = recv(info->a, (char *)tmp_buffer, recv_buf_size, 0);
					if (read_status == 0) {
						// Check if there is anything
						if (total_rx == 0) {
							printf("[!] Gracefully closing binding. *%d<->%d\n", info->a, info->b);
							info->This->error_handler(&info->a, &info->b, info->This);
							ExitThread(0);
						} else {
							printf("[!] Gracefully closing binding. *%d<->%d. Sending remaining %d\n", info->a, info->b, total_rx);
							socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->a, info->b);
							info->This->data_handler(new_data);
							delete new_data;
							info->This->error_handler(&info->a, &info->b, info->This);
							ExitThread(0);
						}
					} else if (read_status == SOCKET_ERROR) {
						printf("[!] SOCKET_ERROR. Closing binding. %d<->%d. Sending remaining %d\n", info->a, info->b, total_rx);
						if (total_rx != 0) {
							socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->a, info->b);
							info->This->data_handler(new_data);
							delete new_data;
						}
						info->This->error_handler(&info->a, &info->b, info->This);
					} 
					
					// Realloc new buffer				
					timeout_iterations = 0;
					total_buffer = (PBYTE)mem::realloc(total_buffer, total_rx + read_status, true);
					mem::copy(&total_buffer[total_rx], tmp_buffer, read_status);
					total_rx += read_status;
					if (read_status != recv_buf_size) {
						// Partially read buffer (insufficient data). No more info, so send out
						printf("[+] Sent %d bytes received on 0x%08x to 0x%08x (request!)\n", total_rx, info->a, info->b);
						socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->a, info->b);
						info->This->data_handler(new_data);
						delete new_data;
						FD_CLR(info->a, &readfds);
						break;
					} else if (read_status == recv_buf_size) {
						// recv_buf_size read.
						cSleep(10);
						continue;
					}
				}
			}

			if (FD_ISSET(info->b, &readfds)) {
				// client->server (a->b)
				PBYTE total_buffer = NULL;
				UINT total_rx = 0;
				while (TRUE) {
					BYTE tmp_buffer[recv_buf_size] = {0};
					INT read_status = recv(info->b, (char *)tmp_buffer, recv_buf_size, 0);
					if (read_status == 0) {
						// Check if there is anything
						if (total_rx == 0) {
							printf("[!] Gracefully closing binding. *%d<->%d\n", info->b, info->a);
							info->This->error_handler(&info->a, &info->b, info->This);
							ExitThread(0);
						} else {
							printf("[!] Gracefully closing binding. %d<->%d. Sending remaining %d\n", info->b, info->a, total_rx);
							socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->b, info->a);
							info->This->data_handler(new_data);
							delete new_data;
							info->This->error_handler(&info->a, &info->b, info->This);
							ExitThread(0);
						}
					} else if (read_status == SOCKET_ERROR) {
						printf("[!] SOCKET_ERROR. Closing binding. *%d<->%d. Sending remaining %d\n", info->b, info->a, total_rx);
						if (total_rx != 0) {
							socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->b, info->a);
							info->This->data_handler(new_data);
							delete new_data;
						}
						info->This->error_handler(&info->a, &info->b, info->This);
					} 
					
					// Realloc new buffer				
					timeout_iterations = 0;
					total_buffer = (PBYTE)mem::realloc(total_buffer, total_rx + read_status, true);
					mem::copy(&total_buffer[total_rx], tmp_buffer, read_status);
					total_rx += read_status;
					if (read_status != recv_buf_size) {
						// Partially read buffer (insufficient data). No more info, so send out
						printf("[+] Sent %d bytes received on 0x%08x to 0x%08x (request!)\n", total_rx, info->b, info->a);
						socket_tools::data *new_data = new socket_tools::data(total_buffer, total_rx, info->b, info->a);
						info->This->data_handler(new_data);
						delete new_data;
						FD_CLR(info->b, &readfds);
						break;
					} else if (read_status == recv_buf_size) {
						// recv_buf_size read.
						cSleep(10);
						continue;
					}
				}
			}
		}
	}
	printf("[!] Timeout on binding: %d<->%d\n", info->a, info->b);
	info->This->error_handler(&info->a, &info->b, info->This);
}*/

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
			info->_io_thread_select_timeout_s, info->_io_thread_select_timeout_ms, &buffer, &buffer_size);
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

socket_tools::socket_bind *socket_tools::bind_sockets(SOCKET i, SOCKET b, socket_data *sa, socket_data *sb,
	error_callback error_handler, data_callback data_handler, __in const types::TIME32 io_thread_select_timeout_s,
	__in const types::TIME32 io_thread_select_timeout_ms)
{
	if (error_handler == NULL) return NULL;

	socket_tools::socket_bind::PSOCKET_TIMEOUTS timings = new socket_tools::socket_bind::SOCKET_TIMEOUTS();
	timings->_timeout_io_thread_select_s	= io_thread_select_timeout_s;
	timings->_timeout_io_thread_select_ms	= io_thread_select_timeout_ms;
	socket_tools::socket_bind *bound_sockets = new socket_tools::socket_bind(sa, sb, error_handler, data_handler,
		timings);
	delete timings;

	return bound_sockets;
}

// socket_data wrapper
socket_tools::ER_WAIT_AND_READ socket_tools::wait_and_read(__in socket_tools::socket_data& rx_socket,
	__in const types::TIME32 time_s, __in const types::TIME32 time_u, __inout socket_tools::data** buffer_data)
{
	SOCKET current_socket = rx_socket.get_socket();
	if (current_socket == INVALID_SOCKET) {
		return ER_WAIT_SOCKET_FAILURE;
	}

	LPVOID buffer;
	UINT buffer_size;
	socket_tools::ER_WAIT_AND_READ wait_status = wait_and_read(current_socket, time_s, time_u, &buffer, &buffer_size);
	if (wait_status == socket_tools::ER_WAIT_OK) {
		*buffer_data = new socket_tools::data(buffer, buffer_size, current_socket, INVALID_SOCKET);
		
		return wait_status;
	} 

	*buffer_data = NULL;

	return wait_status;

	//socket_tools::ER_WAIT_AND_READ wait_status = wait_and_read(current_socket,
	//	time_s, time_u, buffer, buffer_size);

	//return wait_status;
}

socket_tools::ER_WAIT_AND_READ socket_tools::wait_and_read(__in SOCKET rx_socket, 
	__in const types::TIME32 time_s, __in const types::TIME32 time_u, __inout LPVOID *buffer, __out PUINT buffer_size)
{
#ifndef WAIT_AND_READ_NEW_ALGORITHM
	if (rx_socket == INVALID_SOCKET) return ER_WAIT_FAIL;

	*buffer			= NULL;
	*buffer_size	= 0;

	struct timeval timed;

	UINT total_rx			= 0;
	PBYTE total_buffer		= NULL;
	PBYTE tmp_buf			= (PBYTE)mem::malloc(recv_buf_size);

	fd_set readfds;

	bool one_iteration = false;

	while (TRUE) {
		mem::zeromem(&timed, sizeof(struct timeval));
		timed.tv_sec			= time_s;
		timed.tv_usec			= time_u;

		FD_ZERO(&readfds);
		FD_SET(rx_socket, &readfds);
		INT	select_status = select(rx_socket, &readfds, NULL, NULL, &timed);
		if (select_status == SOCKET_ERROR) {
			break;
		} else if (readfds.fd_count == 0) {
			break;
		}

		// There is data waiting to be read
		while (TRUE) {
			mem::zeromem(tmp_buf, recv_buf_size);
			INT read_status = recv(rx_socket, (char *)tmp_buf, recv_buf_size, 0);
			if (read_status == 0) {
				// Gracefully closed
				if (one_iteration == true) {
					goto loop_exit;
				} else {
					one_iteration = true;
					break;
				}
			} else if (read_status == INVALID_SOCKET) {
				// SOCKET_ERROR
				goto loop_exit;
			}

			if (total_rx == 0) {
				total_buffer = (PBYTE)mem::malloc(read_status);
				mem::copy(total_buffer, tmp_buf, read_status);
				total_rx	+= read_status;
			} else {
				total_buffer = (PBYTE)mem::realloc(total_buffer, total_rx + read_status, true);
				mem::copy(&total_buffer[total_rx], tmp_buf, read_status);
				total_rx	+= read_status;
			}

			if (read_status < recv_buf_size) {
				goto loop_exit;
			}

			cSleep(recv_iter); // Time between iterations.
		}

		cSleep(50);
	}


loop_exit:
	if (total_rx == 0) {
#ifdef DEBUG_OUT
		//DBGOUT("[!] Nothing received on 0x%08x\n", rx_socket);
#endif
		*buffer			= NULL;
		*buffer_size	= 0;

		return ER_WAIT_NOTHING_RECEIVED;
	}
	
	*buffer			= total_buffer;
	*buffer_size	= total_rx;

	mem::free(tmp_buf);

	return ER_WAIT_OK;
#else
	if (rx_socket == INVALID_SOCKET) return ER_WAIT_FAIL;

	*buffer			= NULL;
	*buffer_size	= 0;

	struct timeval timed;

	UINT total_rx			= 0;
	PBYTE total_buffer		= NULL;
	PBYTE tmp_buf			= (PBYTE)mem::malloc(recv_buf_size);

	fd_set readfds;

	INT byte_received = 0;
	while (true) {
		mem::zeromem(&timed, sizeof(struct timeval));
		timed.tv_sec			= time_s;
		timed.tv_usec			= time_u;

		FD_ZERO(&readfds);
		FD_SET((unsigned int)rx_socket, &readfds);
		select(rx_socket + 1, &readfds, NULL, NULL, &timed);

		if (!(FD_ISSET(rx_socket, &readfds))) {
			break;
		}

		byte_received = recv(rx_socket, (char *)tmp_buf, recv_buf_size, 0);
		if (byte_received == -1) {
			break;
		}
		if (byte_received == 0 || (byte_received < recv_buf_size)) {
			break;
		}

		if (total_rx == 0) {
			*buffer = (LPVOID)mem::malloc(byte_received);
			mem::copy(*buffer, tmp_buf, byte_received);
		} else {
			*buffer = (LPVOID)mem::realloc(*buffer, total_rx + byte_received, true);
			mem::copy((LPVOID)((DWORD_PTR)*buffer + total_rx), tmp_buf, byte_received);
		}

		total_rx += byte_received;
	}

	// Process remainder, if any
	if (byte_received > 0 && byte_received < recv_buf_size) {
		if (total_rx == 0) {
			*buffer = (LPVOID)mem::malloc(byte_received);
			mem::copy(*buffer, tmp_buf, byte_received);
		} else {
			*buffer = (LPVOID)mem::realloc(*buffer, total_rx + byte_received, true);
			mem::copy((LPVOID)((DWORD_PTR)*buffer + total_rx), tmp_buf, byte_received);
		}

		total_rx += byte_received;
	}

	if (total_rx == 0) {
		mem::free(*buffer);
		*buffer = NULL;

		return ER_WAIT_NOTHING_RECEIVED;
	}

	*buffer_size = total_rx;
	return ER_WAIT_OK;

#endif
	/*
	struct timeval timed;
	mem::zeromem(&timed, sizeof(struct timeval));
	timed.tv_sec			= time_s;
	timed.tv_usec			= time_u;
	fd_set read_flags, write_flags;
	FD_ZERO(&read_flags);
	FD_ZERO(&write_flags);
	FD_SET(0, &write_flags);
	FD_SET(rx_socket, &read_flags);

	PUCHAR rx_buffer		= (PUCHAR)mem::malloc(str::ASCII_CHAR);
	UINT rx_buffer_length	= str::ASCII_CHAR;
	while (TRUE) {
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
	*/
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

socket_tools::stream *socket_tools::find_stream(__in const socket_tools::data *d)
{
	SOCKET data_socket = d->get_socket(socket_tools::data::TYPE_SOURCE);
	if (data_socket == INVALID_SOCKET) return NULL;

	for (std::vector<stream *>::iterator i = socket_tools::stream_array->begin(); 
		i != socket_tools::stream_array->end(); i++) {

		if (data_socket == (*i)->get_socket(socket_tools::stream::TYPE_SRC)->get_socket()) {
			return (*i);
		}
	}

	return NULL;
}

socket_tools::ST_LISTEN_ERROR socket_tools::start_listener_thread(
	__in const socket_tools::listen_callback accept_handler,
	__in const WORD port)
{

	if (socket_tools::wsadata == NULL) {
		socket_tools::wsadata = (WSADATA *)mem::malloc(sizeof(WSADATA));
		ERROR_CODE wsa_status = WSAStartup(MAKEWORD(2, 2), socket_tools::wsadata);
		if (wsa_status) {
#ifdef DEBUG_OUT
			DBGOUT("socket: Failed to initialize WSA\n");
#endif
			return ST_LISTEN_ERROR_START_LISTENER_THREAD;
		}
	}

	SOCKET bind_socket	= INVALID_SOCKET;
	bind_socket			= socket(AF_INET, SOCK_STREAM, 0);
	if (bind_socket == INVALID_SOCKET) {
		WSACleanup();
		return ST_LISTEN_ERROR_START_LISTENER_THREAD;
	}

	static const char opt_data = 1;
	ERROR_CODE opt_status	= setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, &opt_data, sizeof(opt_data));
	opt_status				= setsockopt(bind_socket, SOL_SOCKET, SO_KEEPALIVE, &opt_data, sizeof(opt_data));
	if (opt_status) {
		closesocket(bind_socket);
		return ST_LISTEN_ERROR_START_LISTENER_THREAD;
	}

	struct sockaddr_in server_addr;
	mem::zeromem(&server_addr, sizeof(sockaddr_in));
	server_addr.sin_family				= AF_INET;
	server_addr.sin_port				= htons(port);
	server_addr.sin_addr.S_un.S_addr	= INADDR_ANY;
	ERROR_CODE bind_status = bind(bind_socket, (const sockaddr *)&server_addr, sizeof(sockaddr_in));
	if (bind_status == INVALID_SOCKET) {
		closesocket(bind_socket);
		return ST_LISTEN_ERROR_START_LISTENER_THREAD;
	}

	struct socket_tools::_socket_parm_internal *internal_parameters = (struct socket_tools::_socket_parm_internal *)
		mem::malloc(sizeof(socket_tools::_socket_parm_internal));
	internal_parameters->accept_handler = accept_handler;
	internal_parameters->bind_socket	= bind_socket;
	internal_parameters->port			= port;
	internal_parameters->wait_after_createthread	= socket_tools::time_to_wait_createthread;
	internal_parameters->listener_handle			= cCreateThread(	NULL,
																		0,
																		(LPTHREAD_START_ROUTINE)socket_tools::listener_thread,
																		(LPVOID)internal_parameters,
																		0,
																		NULL);
	if (internal_parameters->listener_handle == NULL) {
		closesocket(bind_socket);
		mem::free(internal_parameters);
		return ST_LISTEN_ERROR_START_LISTENER_THREAD;
	}

	return ST_LISTEN_ERROR_OK;
}

static socket_tools::SOCKET_THREAD_ENTRY __st_thread_conv socket_tools::listener_thread(
	__in const struct socket_tools::_socket_parm_internal *internal_parameters)
{
	socket_tools::number_of_threads_started = 0;

	while (TRUE) {
		fd_set listen_fds;
		//mem::zeromem(&listen_fds, sizeof(fd_set));
		FD_ZERO(&listen_fds);
		FD_SET(internal_parameters->bind_socket, &listen_fds);
		ERROR_CODE listen_status = listen(internal_parameters->bind_socket, SOMAXCONN);
		if (listen_status == INVALID_SOCKET) {
			continue;
		}

		socket_tools::PLISTEN_PARAMETER parameters = (socket_tools::PLISTEN_PARAMETER)mem::malloc(
			sizeof(socket_tools::LISTEN_PARAMETER));
		parameters->bind_socket = internal_parameters->bind_socket;

		INT junk = sizeof(struct sockaddr);
		parameters->accept_socket	= accept(parameters->bind_socket, 
			&parameters->client_info, (int *)&junk);
		if (parameters->accept_socket == INVALID_SOCKET) {
			mem::free(parameters);
			continue;
		}

		parameters->listener_thread	= cCreateThread(	NULL,
														0,
														(LPTHREAD_START_ROUTINE)internal_parameters->accept_handler,
														(LPVOID)parameters,
														0,
														NULL);
		if (parameters->listener_thread == NULL) {
			mem::free(parameters);
			continue;
		}

		number_of_threads_started++;

		cSleep(internal_parameters->wait_after_createthread);
	}
}

socket_tools::socket_data::WAIT_ERROR socket_tools::socket_data::wait_for_data(
	__in const types::TIME32 time_s, __in const types::TIME32 time_ms)
{
	if (this->is_data_available == true) {
		return WAIT_ERROR_DATA_WAITING;
	}

	if (this->WaitData != NULL) {
		this->WaitData.clear();
	}

	LPVOID buffer;
	UINT buffer_size;
	socket_tools::ER_WAIT_AND_READ wait_status = wait_and_read(
		this->socket_handle, time_s, time_ms, &buffer, &buffer_size);
	if (wait_status == ER_WAIT_FAIL) {
		return WAIT_ERROR_FAILURE;
	} else if (wait_status == ER_WAIT_NOTHING_RECEIVED) {
		return WAIT_ERROR_NOTHING_RECEIVED;
	} else if (wait_status == ER_WAIT_TIMEOUT) {
		return WAIT_ERROR_NOTHING_RECEIVED;
	}

#ifdef USE_SOCKET_ENCRYPTION

	Buffer2 EncryptedBuffer = new mem::buffer2(buffer, buffer_size);
	mem::free(buffer);
	Buffer2 DecryptedBuffer = this->EncryptedChannel->decrypt(*EncryptedBuffer);
	this->WaitData = new socket_tools::data(**DecryptedBuffer, 
		DecryptedBuffer->get_raw_size(),
		this->socket_handle, 
		INVALID_SOCKET);
	this->is_data_available = true;

	return WAIT_ERROR_DATA_AVAILABLE;

#else

	this->WaitData = new socket_tools::data(buffer, buffer_size, this->socket_handle, INVALID_SOCKET);
	this->is_data_available = true;

	mem::free(buffer);

	return WAIT_ERROR_DATA_AVAILABLE;

#endif
}


// Encryption subroutines
#ifdef USE_SOCKET_ENCRYPTION

bool socket_tools::socket_data::setup_encryption_client(void)
{
	this->EncryptedChannel = new crypt::channel_client(&this->socket_handle);

	return this->EncryptedChannel->process_initial(&this->socket_handle);
}

#endif

#ifdef USE_SOCKET_ENCRYPTION

bool socket_tools::socket_data::setup_encryption_server(void)
{
	this->EncryptedChannel = new crypt::channel_server(&this->socket_handle);

	return this->EncryptedChannel->process_initial(&this->socket_handle);
}

#endif