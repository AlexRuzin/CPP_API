#include <Windows.h>
#include <vector>

#include "crypt.h"

#include "common/str.h"
#include "net/socket.h"

using namespace crypt;

namespace crypt {
	HCRYPTPROV crypt_provider = NULL;

	static HCRYPTPROV acquire_provider(void)
	{
		if (crypt_provider == 0) {
			BOOL acquire_status = CryptAcquireContextA(
				&crypt::crypt_provider,
				NULL,
				NULL,
				PROV_RSA_FULL,
				CRYPT_VERIFYCONTEXT);
			if (acquire_status == FALSE) {
				return 0;
			}
		}

		return crypt_provider;
	}
}

DWORD crypt::murmur_hash(LPCSTR key, UINT length, DWORD seed)
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.

	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value

	unsigned int h = seed ^ length;

	// Mix 4 bytes at a time into the hash

	const unsigned char * data = (const unsigned char *)key;

	while(length >= 4)
	{
		unsigned int k = *(unsigned int *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		h *= m; 
		h ^= k;

		data += 4;
		length -= 4;
	}
	
	// Handle the last few bytes of the input array

	switch(length)
	{
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
			h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}



BYTE crypt::generate_random_byte_range(UINT high) 
{
	HCRYPTPROV				provider = acquire_provider();
	if (provider == 0) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed to aquire cryptographic provider.\n");
#endif
		DebugBreak();
	}
	BYTE					data[64]			= {0};
	UINT					i;

	if (high == 0) {
		return 0;
	}

	//Sleep(10);
	/*
	if (!CryptAcquireContextA(		&provider,
									NULL,
									NULL,
									PROV_RSA_FULL,
									CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	*/

	ZeroMemory(data, sizeof(data));
	data[0] = (BYTE)(high + 1);
	while (data[0] > high) {

		CryptGenRandom(provider, 32, data);

		for (i = 1; i < 64; i++) {

			data[0] ^= data[i];

			if (data[0] < high + 1) {
				break;
			}
		}
	}

	BYTE out = data[0];
	//CryptReleaseContext(provider, 0);

	return out;
}

std::vector<BYTE> *crypt::generate_md5(__in const LPVOID buffer, __in const UINT size, 
									   __outopt HCRYPTHASH *hash_out, __outopt HCRYPTKEY *key_out,
									   __outopt HCRYPTPROV *provider_out)
{
	BYTE md5_array[crypt::md5_length];
	mem::zeromem(md5_array, md5_length);

	HCRYPTPROV provider = acquire_provider();
	if (provider == 0) {
		return NULL;
	}

	HCRYPTHASH hash;
	BOOL crypt_status = CryptCreateHash(provider, CALG_MD5, 0, 0, &hash);
	if (!crypt_status) {
		//CryptReleaseContext(provider, 0);
		return NULL;
	}
	
	crypt_status = CryptHashData(hash, (const BYTE *)buffer, size, 0);
	if (!crypt_status) {
		//CryptReleaseContext(provider, 0);
		CryptDestroyHash(hash);
		return NULL;
	}

	crypt_status = CryptGetHashParam(hash, HP_HASHVAL, md5_array, (PDWORD)&crypt::md5_length, 0);
	if (crypt_status) {
		//CryptReleaseContext(provider, 0);						 
		CryptDestroyHash(hash);
		return NULL;
	}

	if (hash_out == NULL && key_out == NULL && provider_out == NULL) {
		//cCryptReleaseContext(provider, 0);  
		cCryptDestroyHash(hash);
	}

	if (key_out != NULL) {
		HCRYPTKEY key = 0;
		BOOL derive_result = CryptDeriveKey(	provider,
												CALG_RC4,
												hash,
												CRYPT_EXPORTABLE,
												&key);
		*key_out = key;
		*provider_out = provider;
		*hash_out = hash;
	}

	std::vector<BYTE> *md5_array_vector = new std::vector<BYTE>;
	md5_array_vector->reserve(md5_length);
	for (UINT i = 0; i < md5_length; i++) {
		md5_array_vector->push_back(md5_array[i]);
	}
	return md5_array_vector;
}

crypt::GEN_ERROR crypt::generate_random_buffer(__inout LPVOID *out, __in const UINT size)
{
	if (size == 0) return ER_FAIL;

	HCRYPTPROV						provider = acquire_provider();
	if (provider == 0) {
		return ER_FAIL;
	}
	/*
	if (!CryptAcquireContextA(		&provider,
									NULL,
									NULL,
									PROV_RSA_FULL,
									CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	*/

	LPVOID out_buffer = (LPVOID)mem::malloc(size);
	CryptGenRandom(provider, size, (PBYTE)out_buffer);	

	*out = out_buffer;

	return ER_OK;
}

mem::buffer2 *crypt::encrypt_xor_shift(__in crypt::md5 const& key, __in mem::buffer2 const& raw_data,
	__in const ENCRYPT_MODE mode)
{
	PBYTE buffer;
	UINT buffer_size;

	raw_data.get_raw_data((LPVOID *)&buffer, &buffer_size);
	if (buffer == NULL || buffer_size == 0) {
		return NULL;
	}

	PBYTE ptr, encrypted_buffer = ptr = (PBYTE)mem::malloc(buffer_size);
	crypt::ARRAY::iterator key_counter = key.get_array()->begin();
	for (UINT buffer_counter = 0; buffer_counter < buffer_size; buffer_counter++, key_counter++) {
		if (key_counter == key.get_array()->end()) {
			key_counter = key.get_array()->begin();
		}

		//if (*(PBYTE)&buffer[buffer_counter] == 0) {
		//	continue;
		//}

		*(PBYTE)&encrypted_buffer[buffer_counter] = *(PBYTE)&buffer[buffer_counter] ^ *key_counter;
	}

	mem::buffer2 *new_buffer = new mem::buffer2(encrypted_buffer, buffer_size);
	mem::free(encrypted_buffer);

	return new_buffer;
}

// Processes the encryption layer request from the client
crypt::channel_server::channel_server(__in SOCKET *current_connection)
{
	this->connected_to_client = false;
	this->request = new key_request();
	this->RemoteHostname = NULL;

	return;
}

// Sends the encryption layer request to the server
crypt::channel_client::channel_client(__in SOCKET *current_connection)
{
	this->connected_to_server = false;

	this->request		= new key_request();

	this->client_socket	= current_connection;

	this->Hostname		= get_host_name();
	this->Key			= get_key(*this->Hostname, crypt::channel_seed);

	mem::copy(this->request->hostname, **this->Hostname, this->Hostname->lenA());
	this->request->hostname_len = this->Hostname->lenA();

	return;
}

bool crypt::channel_client::process_initial(__inout SOCKET *current_socket)
{
	if (*current_socket != *this->client_socket) {
		return false;
	}

	INT send_status = send(*current_socket, (const char *)this->request, sizeof(KEY_REQUEST), 0);
	if (send_status != sizeof(KEY_REQUEST)) {
		return false;
	}

	// Receive response
	LPVOID response_buffer = NULL;
	UINT response_buffer_size = 0;
	socket_tools::ER_WAIT_AND_READ wait_status = socket_tools::wait_and_read(
		*current_socket, crypt::crypt_channel_timeout, 0, &response_buffer, &response_buffer_size);
	if (wait_status != socket_tools::ER_WAIT_OK || 
		response_buffer == NULL ||
		response_buffer_size != sizeof(crypt::channel_response_ok)) 
	{
		if (response_buffer != NULL) mem::free(response_buffer);
		return false;
	}

	/*
	CHAR response_buffer[sizeof(crypt::channel_response_ok)] = {0};
	INT bytes_received = recv(*current_socket, (char *)response_buffer, sizeof(response_buffer), 0);
	if (bytes_received != sizeof(response_buffer)) {
		return false;
	}
	*/

	// Decrypt buffer, and test for OK
	Buffer2 ResponseBuffer = new mem::buffer2((const LPVOID)response_buffer, response_buffer_size);
	Buffer2 DecryptedResponseBuffer = get_decrypted_buffer(*ResponseBuffer, this->Key->get_crypt_key());

	if (DecryptedResponseBuffer->get_raw_size() != sizeof(crypt::channel_response_ok)) {
		return false;
	}

	if (mem::compare(**DecryptedResponseBuffer,
		crypt::channel_response_ok, DecryptedResponseBuffer->get_raw_size())) 
	{
		return false;
	}

	this->connected_to_server = true;

	return true;
}

bool crypt::channel_server::process_initial(__inout SOCKET *current_socket)
{
	key_request *request = NULL;
	UINT request_size = 0;
	socket_tools::ER_WAIT_AND_READ wait_status = socket_tools::wait_and_read(
		*current_socket, crypt::crypt_channel_timeout, 0, (LPVOID *)&request, &request_size);
	if (wait_status != socket_tools::ER_WAIT_OK || request_size != sizeof(key_request) ||
		request->hostname[0] == '\0' ||
		request->hostname_len > (MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR) ||
		request->hostname[MAX_COMPUTERNAME_LENGTH] != '\0') {
		if (request != NULL) {
			mem::free(request);
		}
		return false;
	}	

	/*
	key_request request;
	mem::zeromem((LPVOID)&request, sizeof(key_request));
	INT bytes_received = recv(*current_socket, (char *)&request, sizeof(key_request), 0);
	if (bytes_received != sizeof(key_request) || request.hostname[0] == '\0' || 
		request.hostname_len > (MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR) || 
		request.hostname[MAX_COMPUTERNAME_LENGTH] != '\0') {
		return false;
	}
	*/

	if (!str::is_charA((LPCSTR)request->hostname, request->hostname_len)) {
		return false;
	}

	// Generate key
	//this->Key = new md5((const LPVOID)request.hostname, request.hostname_len);
	this->RemoteHostname = new str_string(request->hostname);
	this->Key = get_key(*this->RemoteHostname, crypt::channel_seed);

	// Send response
	Buffer2 DecryptedResponse = new mem::buffer2((const LPVOID)crypt::channel_response_ok, 
		sizeof(crypt::channel_response_ok));
	Buffer2 EncryptedResponse = get_encrypted_buffer(*DecryptedResponse, this->Key->get_crypt_key());

	INT bytes_sent = send(*current_socket, (const char *)**EncryptedResponse, 
		EncryptedResponse->get_raw_size(), 0);
	if (bytes_sent != DecryptedResponse->get_raw_size()) {
		return false;
	}

	cSleep(500);

	this->connected_to_client = true;
	
	return true;
}

// Gets the md5 data for key. XORs with a static DWORD
crypt::md5* crypt::channel::get_key(__in const str_string& host_name, __in const DWORD seed)
{
	// XOR hostname with static key
	LPVOID raw_data = (LPVOID)mem::malloc(host_name.lenA());
	mem::copy(raw_data, (LPCVOID)*host_name, host_name.lenA());

	PBYTE raw_data_ptr = (PBYTE)raw_data;
	for (UINT i = 0, seed_index = 0; i < host_name.lenA(); i++, seed_index++, raw_data_ptr++) {
		if (seed_index == sizeof(seed)) seed_index = 0;

		*raw_data_ptr = *raw_data_ptr ^ (BYTE)(seed >> (seed_index * sizeof(DWORD)));
	}

	return new md5(raw_data, host_name.lenA());
}

// Returns the hostname
str_string *crypt::channel_client::get_host_name(void) const
{
	CHAR hostname[MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR] = {0};
	UINT hostname_size = MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR;
	BOOL get_status = GetComputerNameA((LPSTR)hostname, (LPDWORD)&hostname_size);
	if (get_status == FALSE) {
		return NULL;
	}

	if (hostname[0] == '\0') {
		return NULL;
	}	  

	str_string *return_buffer = new str_string(hostname);
	return return_buffer;
}

inline crypt::channel::~channel(void)
{
	if (this->request != NULL) {
		delete this->request;
		this->request = NULL;
	}
}

mem::buffer2 *crypt::channel::get_decrypted_buffer(	__in const mem::buffer2& encrypted_buffer,
													__in const HCRYPTKEY key) const
{
	LPVOID decrypted_buffer = (LPVOID)mem::malloc(encrypted_buffer.get_raw_size());
	mem::copy(decrypted_buffer, *encrypted_buffer, encrypted_buffer.get_raw_size());
	DWORD raw_size = encrypted_buffer.get_raw_size();
	BOOL decrypt_status = CryptDecrypt(key, 0, TRUE, 0, (BYTE *)decrypted_buffer, &raw_size);
	if (!decrypt_status) {
		mem::free(decrypted_buffer);
		return NULL;
	}

	if (raw_size != encrypted_buffer.get_raw_size()) {
		DebugBreak();
	}

	mem::buffer2 *out_buffer = new mem::buffer2(decrypted_buffer, raw_size);
	mem::free(decrypted_buffer);

	return out_buffer;
}

mem::buffer2 *crypt::channel::get_encrypted_buffer(	__in const mem::buffer2& decrypted_buffer,
													__in const HCRYPTKEY key) const
{
	LPVOID encrypted_buffer = (LPVOID)mem::malloc(decrypted_buffer.get_raw_size());
	mem::copy(encrypted_buffer, *decrypted_buffer, decrypted_buffer.get_raw_size());
	DWORD raw_size = decrypted_buffer.get_raw_size();
	BOOL encrypt_status = CryptEncrypt(key, 0, TRUE, 0, (BYTE *)encrypted_buffer, &raw_size, raw_size);
	if (!encrypt_status) {
		mem::free(encrypted_buffer);
		return NULL;
	}

	if (raw_size != decrypted_buffer.get_raw_size()) {
		DebugBreak();
	}

	mem::buffer2 *out_buffer = new mem::buffer2(encrypted_buffer, raw_size);
	mem::free(encrypted_buffer);

	return out_buffer;
}

mem::buffer2 *crypt::channel::decrypt(__in const mem::buffer2& encrypted_buffer) const
{
	return get_decrypted_buffer(encrypted_buffer, this->Key->get_crypt_key());
}

mem::buffer2 *crypt::channel::encrypt(__in const mem::buffer2& decrypted_buffer) const
{
	return get_encrypted_buffer(decrypted_buffer, this->Key->get_crypt_key());
}

encryption_buffer::encryption_buffer(__in const crypt::md5& key, __in const mem::buffer2& data, __in const bool is_encrypted)
{
	
	this->Key				= new md5(key.get_array());

	if (is_encrypted == true) {
		//Data is already encrypted
		this->EncryptedData = new mem::buffer2(data);

		this->is_encrypted = true;
	} else {
		this->DecryptedData = new mem::buffer2(data);

		this->is_encrypted = false;
	}

	return;
}

bool encryption_buffer::encrypt(void)
{
	if (this->Key.get_value() == NULL) { 
		return false;
	}

	this->EncryptedData = crypt::encrypt_xor_shift(*this->Key, *this->DecryptedData, ENCRYPT_MODE_ENCRYPT);
	if (this->EncryptedData.get_is_null()) {
		return true;
	}

	this->DecryptedData.clear();

	this->is_encrypted = true;

	return true;
}

bool encryption_buffer::decrypt(void)
{
	if (this->Key.get_is_null()) {
		return false;
	}

	this->DecryptedData = crypt::encrypt_xor_shift(*this->Key, *this->EncryptedData, ENCRYPT_MODE_DECRYPT);
	if (this->EncryptedData.get_is_null()) {
		return false;
	}

	this->EncryptedData.clear();

	this->is_encrypted = false;

	return true;
}

const str_string& crypt::md5::get_md5_string(void)
{
	if (this->RawMD5String.get_is_null()) {
		generate_md5_string();
	}

	return *this->RawMD5String.get_value();
}

void crypt::md5::generate_md5_string(void)
{
	if (this->RawMD5String.get_is_null()) {
		StrString OutString = str::byte_vector_to_string((std::vector<BYTE> &)*this->md5_elements);

		this->RawMD5String = new str_string(**OutString);
	} 

	return;
}