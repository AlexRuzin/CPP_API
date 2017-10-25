#include <Windows.h>

#include "net_download.h"

#include "debug/debug.h"
#include "common/str.h"
#include "common/mem.h"

using namespace download;

#ifdef XTP_ENABLE

//#ifdef XTP_MODE_CLIENT
// Client mode XTP methods
xtp_client::xtp_client(__in const url_library::url& request_url)
{
	this->download_ok = false;

	if (request_url.get_is_ok() == false) {
		return;
	}

	this->RequestURL = new url_library::url(request_url.get_raw_url());

	// Parse url
	this->Hostname = request_url.get_hostname();
	this->Filename = request_url.get_filename();

	this->ReturnData = NULL;

	return;
}

bool xtp_client::process(void)
{
	// Connect to remote server
	Ptr<socket_tools::socket_data::init_socket_data> InitData =
		new socket_tools::socket_data::init_socket_data();
	InitData->type			= socket_tools::socket_data::TYPE_DOMAIN;
	InitData->domain		= new str_string(this->Hostname->to_lpstr());
	InitData->port			= download::xtp_service_port;
	this->CurrentConnection = new socket_tools::socket_data(InitData.get_value());
	bool is_connected = this->CurrentConnection->get_is_connected();
	if (is_connected == false) {
		this->CurrentConnection = NULL;
		return false;
	}

#ifdef XTP_ENCRYPTION
	bool channel_status = this->CurrentConnection->setup_encryption_client();
	if (channel_status == false) {
		return false;
	}
#endif

	// Generate physical structures
	Ptr<xtp::request> Request = new xtp::request();
	mem::copy(Request->signature, _sig_xtp, _sig_size);
	mem::copy(Request->url, this->RequestURL->get_raw_url(), str::lenA(this->RequestURL->get_raw_url()));
	mem::copy(Request->type, _sig_xtp_request, _sig_size);

	// Send
	Buffer2 RawRequest = new mem::buffer2((const LPVOID)Request.get_value(), sizeof(xtp::request));
	bool send_status = this->CurrentConnection->send_data(*RawRequest);
	if (send_status == false) {
		return false;
	}

	// Parse response header
	Ptr<xtp::request> ResponseHeader = NULL;
	socket_tools::socket_data::WAIT_ERROR wait_status = 
		this->CurrentConnection->wait_for_data(xtp_wait_seconds, 0);
	if (wait_status == socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
		// Data received. Check for the appropriate response header
		LPVOID raw_buffer		= NULL;
		UINT raw_buffer_size	= 0;
		socket_tools::data *raw_data = this->CurrentConnection->wait_for_data_get_data(
			&raw_buffer, &raw_buffer_size);
		mem::buffer2 *received_buffer = raw_data->get_buffer();

		if (received_buffer->get_raw_size() != sizeof(xtp::request)) {
			return false;
		}

		ResponseHeader = new xtp::request();
		mem::copy(ResponseHeader.get_value(), 
			received_buffer->get_raw_buffer(), received_buffer->get_raw_size());

		// Parse
		if (str::compareA(ResponseHeader->signature, _sig_xtp, _sig_size) ||
			str::compareA(ResponseHeader->type, _sig_xtp_response_ok, _sig_size) ||
			ResponseHeader->response_size == 0) 
		{
			return false;
		}

	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_DATA_WAITING) {
		return false;
	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_NOTHING_RECEIVED) {
		return false;
	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_FAILURE) {
		return false;
	}

	// Send response (send back 1 byte (0x41)
	Buffer2 SecondResponseBuffer = new mem::buffer2(1);
	*(PBYTE)SecondResponseBuffer.get_value()->get_raw_buffer() = xtp_response_ready;
	send_status = this->CurrentConnection->send_data(*SecondResponseBuffer);
	if (send_status == false) {
		return false;
	}

	cSleep(50);

	// Read input until entire buffer is received
	this->ReturnData = NULL;
	wait_status = this->CurrentConnection->wait_for_data(xtp_wait_seconds, 0);
	if (wait_status == socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
		// Process data
		LPVOID buffer = NULL;
		UINT buffer_size = 0;
		socket_tools::data *raw_data = this->CurrentConnection->wait_for_data_get_data(
			&buffer, &buffer_size);

		if (raw_data == NULL) {
			return false;
		}

		if (this->ReturnData.get_is_null()) {
			this->ReturnData = new mem::buffer2(buffer, buffer_size);
		} else {
			this->ReturnData->append(buffer, buffer_size);
		}
	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_NOTHING_RECEIVED) {
		return false;
	} else {
		return false;
	}	  

	// Send final response (0x42)
	Buffer2 ThirdResponseBuffer = new mem::buffer2(1);
	*(PBYTE)ThirdResponseBuffer.get_value()->get_raw_buffer() = xtp_response_ready2;
	send_status = this->CurrentConnection->send_data(*ThirdResponseBuffer);
	if (send_status == false) {
		return false;
	}

	this->download_ok = true; 	
	return true;
}	

//#else
// Server mode XTP methods
xtp_server::xtp_server(__in const std::vector<xtp_server_input *>& object_host_info)
{
	this->service_port = download::xtp_service_port;
	this->listener = INVALID_HANDLE_VALUE;
	mem::zeromem(this->dispatched_handlers, sizeof(dispatched_handlers));

	// Deep copy the info object
	if (object_host_info.size() == 0) {
		this->ObjectHostInfo = NULL;
		return;
	}
	this->ObjectHostInfo = new std::vector<xtp_server_input *>();

	for (std::vector<xtp_server_input *>::const_iterator i = object_host_info.begin();
		i != object_host_info.end(); i++) 
	{
		PXTP_SERVER_INPUT current_structure = new xtp_server_input();

		current_structure->RequestName = new str_string(**(*i)->RequestName);
		current_structure->RawPE = new pe::raw_pe((*i)->RawPE->get_raw_buffer());

		this->ObjectHostInfo->push_back(current_structure);
	}	 

	return;
}

PCRITICAL_SECTION xtp_server::sync_raw_data;
bool xtp_server::process(void)
{
	//this->bind_socket = INVALID_SOCKET;
	this->sync_raw_data = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
	cInitializeCriticalSection(this->sync_raw_data);

	 // Start the listener thread
	this->listener = cCreateThread(	NULL, 0, 
									(LPTHREAD_START_ROUTINE)listener_thread,
									(LPVOID)this->ObjectHostInfo.get_value(),
									0,
									NULL);
	if (this->listener == NULL) {
		return false;
	}

	return true;
}

types::NO_RETURN_VALUE __declspec(noreturn) 
	xtp_server::listener_thread(__in const std::vector<xtp_server_input *> *object_host_info)
{
	// Start WSA
	WSADATA wsadata = {0};
	WSAStartup(MAKEWORD(2, 2), &wsadata);

	SOCKET bind_socket = INVALID_SOCKET;

	bind_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (bind_socket == INVALID_SOCKET) {
		WSACleanup();
		ExitThread(0);
	}

	static const char opt_data = 1;
	setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, &opt_data, sizeof(opt_data));
	setsockopt(bind_socket, SOL_SOCKET, SO_KEEPALIVE, &opt_data, sizeof(opt_data));

	struct sockaddr_in server_addr;
	mem::zeromem(&server_addr, sizeof(sockaddr_in));
	server_addr.sin_addr.S_un.S_addr	= INADDR_ANY;
	server_addr.sin_family				= AF_INET;
	server_addr.sin_port				= htons(download::xtp_service_port);
	ERROR_CODE bind_status = bind(bind_socket, (const sockaddr *)&server_addr, sizeof(sockaddr_in));
	if (bind_status == INVALID_SOCKET) {
		closesocket(bind_socket);
		WSACleanup();
		ExitThread(0);
	}

	// Primary listener loop
	while (true) {
		fd_set listen_fds;
		FD_ZERO(&listen_fds);
		FD_SET(bind_socket, &listen_fds);
		ERROR_CODE listen_status = listen(bind_socket, SOMAXCONN);
		if (listen_status) {
			continue;
		}

		// Accept
		INT junk = sizeof(struct sockaddr_in);
		struct sockaddr_in socket_info = {0};
		SOCKET accepted_socket = accept(bind_socket, (struct sockaddr *)&socket_info, (int *)&junk);
		if (accepted_socket == INVALID_SOCKET) {
			continue;
		}

		handler_thread_parameters *params = new handler_thread_parameters();
		params->current_connection = new socket_tools::socket_data(accepted_socket);
		params->object_host_info = object_host_info;
		mem::copy(&params->connection_data, &socket_info, sizeof(struct sockaddr));

		HANDLE current_thread = cCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)handler_thread, (LPVOID)params, 0, NULL);
		params->tid = current_thread;
	}  
}

types::NO_RETURN_VALUE __declspec(noreturn)
	xtp_server::handler_thread(__in handler_thread_parameters *params)
{
	cSleep(50);
#ifdef XTP_ENCRYPTION
	// Initialize server encryption
	bool channel_status = params->current_connection->setup_encryption_server();
	if (channel_status == false) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to start encrypted channel with %s\n",
			inet_ntoa(params->connection_data.sin_addr));
#endif
		goto fail;
	}
#endif

#ifdef DEBUG_OUT
	 DBGOUT("[%d] Incoming connection from %s...\n", 
		 params->tid, inet_ntoa(params->connection_data.sin_addr));
#endif

	// Recieve the request packet
	socket_tools::socket_data::WAIT_ERROR wait_status = 
		params->current_connection->wait_for_data(download::xtp_wait_seconds, 0);
	if (wait_status == socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
		// Data available
		LPVOID buffer;
		UINT buffer_size;
		socket_tools::data *rx_bytes = 
			params->current_connection->wait_for_data_get_data(&buffer, &buffer_size);
		if (buffer_size != sizeof(xtp::request)) {
			goto fail;
		}

		xtp::request *current_request = (xtp::request *)buffer;
		if (str::compareA(current_request->signature, _sig_xtp, sizeof(_sig_xtp)) || 
			str::compareA(current_request->type, _sig_xtp_request, sizeof(_sig_xtp_request)) ||
			current_request->url[xtp_max_url_length - str::ASCII_CHAR] != '\0' ||
			str::is_charA(current_request->url, str::lenA(current_request->url)) == false)
		{
			goto fail;
		}

		// Attempt to find file
		StrString Filename = isolate_request_file(current_request->url);
		if (Filename.get_is_null()) {
			goto fail;
		}

		Buffer2 RawData = get_raw_data(params->object_host_info, *Filename);
		if (RawData.get_is_null()) {
			goto fail;
		}

		// Send response header
		Ptr<xtp::request> Response = new xtp::request();
		mem::copy(Response->signature, _sig_xtp, sizeof(_sig_xtp));
		mem::copy(Response->type, _sig_xtp_response_ok, sizeof(_sig_xtp_response_ok));
		mem::copy(Response->url, current_request->url, str::lenA(current_request->url));
		Response->response_size = RawData->get_raw_size();
		Buffer2 ResponseBuffer = new mem::buffer2((const LPVOID)Response.get_value(), sizeof(request));
		bool send_status = params->current_connection->send_data(*ResponseBuffer);
		if (send_status == false) {
			goto fail;
		}

		// Wait for ready signal
		buffer = NULL; 
		buffer_size = 0;
		socket_tools::socket_data::WAIT_ERROR wait_status = 
			params->current_connection->wait_for_data(download::xtp_wait_seconds, 0);
		if (wait_status != socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
			goto fail;
		}	
		rx_bytes = params->current_connection->wait_for_data_get_data(&buffer, &buffer_size);
		if (buffer_size != sizeof(BYTE)) {
			goto fail;
		}
		if (*(PBYTE)buffer != xtp_response_ready) {
			goto fail;
		}

		// Send out raw data
		send_status = params->current_connection->send_data(*RawData);
		if (send_status == false) {
			goto fail;
		}

		// Wait for final response
		wait_status = params->current_connection->wait_for_data(download::xtp_wait_seconds, 0);
		if (wait_status != socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
			goto fail;
		}
		rx_bytes = params->current_connection->wait_for_data_get_data(&buffer, &buffer_size);
		if (rx_bytes == NULL || buffer_size != sizeof(BYTE)) {
			goto fail;
		}
		if (*(PBYTE)buffer != xtp_response_ready2) {
			goto fail;
		}

#ifdef DEBUG_OUT
		DBGOUT("[%d] Sent out file %s[%d] to %s\n", 
			params->tid, **Filename, RawData->get_raw_size(), 
			inet_ntoa(params->connection_data.sin_addr));
#endif

		goto cleanup;

	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_DATA_WAITING) {
		goto cleanup;
	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_NOTHING_RECEIVED) {
		goto cleanup;
	} else if (wait_status == socket_tools::socket_data::WAIT_ERROR_FAILURE) {
		goto cleanup;
	}



fail:
#ifdef DEBUG_OUT
	DBGOUT("[!%d] General failure sending file.\n", params->tid);
#endif

cleanup:
	delete params->current_connection;
	params->current_connection = NULL;

	delete params;
}

mem::buffer2 *xtp_server::get_raw_data(__in const std::vector<xtp_server_input *> *object_host_info,
									   __in const str_string& file_name)
{
	//printf("0x%08x", sync_raw_data);
	cEnterCriticalSection(sync_raw_data);

	for (std::vector<xtp_server_input *>::const_iterator i = object_host_info->begin();
		i != object_host_info->end(); i++)
	{
		if (*(*i)->RequestName == file_name) {

			mem::buffer2 *return_buffer = new mem::buffer2(
				(*i)->RawPE->get_raw_buffer()->get_raw_buffer(), 
				(*i)->RawPE->get_raw_buffer()->get_raw_size());

			cLeaveCriticalSection(sync_raw_data);
			return return_buffer;
		}	
	}

	cLeaveCriticalSection(sync_raw_data);
	
	return NULL;
}

// Generates a vector'd list from a file_path
std::vector<xtp_server::xtp_server_input *> *download::generate_list_from_file(__in const str_string& file_path)
{
	// Open file
	Buffer2 RawTextFile = fs::read_raw_into_buffer_(file_path);
	if (RawTextFile.get_is_null()) {
		return NULL;
	}		 

	++*RawTextFile;	//Adds a null to the end of the string
	StrString RawString = new str_string((LPSTR)**RawTextFile);
	Ptr<std::vector<str_string *>> RawTokens = RawString->split_string_by_terminatorA_(NULL, 
		xtp_line_term, str::ASCII_CHAR);
	if (RawTokens->size() == 0) {
		return NULL;
	}

	std::vector<xtp_server::xtp_server_input *> *element_list = 
		new std::vector<xtp_server::xtp_server_input *>();

	for (std::vector<str_string *>::const_iterator i = RawTokens->begin(); 
		i != RawTokens->end(); i++)
	{
		Ptr<std::vector<str_string *>> ElementTokens = (*i)->split_string_by_terminatorA_(NULL, 
			xtp_element_term, str::ASCII_CHAR);
		if (ElementTokens->size() != 2) {
			delete element_list;
			return NULL;
		}

		StrString ElementPath = new str_string((*ElementTokens)[xtp_file_path]->to_lpstr());
		Buffer2 RawFile = fs::read_raw_into_buffer_(*ElementPath);
		if (RawFile.get_is_null()) {
			delete element_list;
			return NULL;
		}

		xtp_server::xtp_server_input *current_element = new xtp_server::xtp_server_input();
		current_element->RequestName = new str_string((*ElementTokens)[xtp_file_name]->to_lpstr());
		current_element->RawPE = new pe::raw_pe(*RawFile);

		element_list->push_back(current_element);
	}							

	return element_list;
}

str_string *xtp::isolate_request_file(__in const CHAR url[xtp_max_url_length])
{
	// In the form of xtp://name/file. Locate single /	  
	PCHAR ptr = (PCHAR)&url[str::lenA(xtp_protocol_uri)];
	if (str::find_character_in_stringA((LPCSTR)ptr, str::lenA(ptr), '/') == false) {
		return NULL;
	}				

	UINT i, max_size = str::lenA(ptr);
	for (i = 0; i < max_size; i++) {
		if (ptr[i] == '/') {
			ptr = (PCHAR)&ptr[i + str::ASCII_CHAR];
			break;
		}
	}

	if (i == max_size) {
		return NULL;
	}

	return new str_string((LPSTR)ptr);
}

#endif
//#endif

