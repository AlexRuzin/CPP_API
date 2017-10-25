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
#pragma message (OUTPUT_PRIMARY "crypt: Compiling 64-bit")
#else 
#pragma message (OUTPUT_PRIMARY "crypt: Compiling 32-bit.")
#endif
#endif

#include "common/mem.h"
#include "common/str.h"
//#include "net/socket.h"

#pragma once

// Preprocessor Config
#define ENCRYPTION_CHANNEL_SEED 0x44a4d3f5

// Preprocessor Constants
#define MD5_LENGTH		16

// Preprocessor function macros
#define CHECK_DELETE(x)	if (x != NULL) delete x

// Timings 
#define CRYPT_CHANNEL_TIMEOUT CONFIG_CRYPT_TIMEOUT

namespace crypt
{
	// Generate random number
	BYTE generate_random_byte_range(UINT high);

	// Murmur hash, 32bit
	DWORD murmur_hash(LPCSTR key, UINT length, DWORD seed);

	// MD5
	class md5;

	typedef BYTE MD5_ELEMENT, *PMD5_ELEMENT;
	static const UINT md5_length			= MD5_LENGTH;
	typedef std::vector<MD5_ELEMENT>		ARRAY;
	std::vector<BYTE> *generate_md5(__in const LPVOID buffer, __in const UINT size, 
									__outopt HCRYPTHASH *hash_out, __outopt HCRYPTKEY *key_out,
									__outopt HCRYPTPROV *provider_out);

	// HCRYPTPROV object is shared by all instances of md5.
	// Furthermore, it is initialized by md5_init()
	extern HCRYPTPROV crypt_provider;

	class md5 {
	private:
		str_string		*string;

		crypt::ARRAY	*md5_elements;

		LPVOID			raw_buffer;
		UINT			raw_buffer_size;

		StrString		RawMD5String;

		bool			state_ok;

		HCRYPTPROV		provider;
		HCRYPTHASH		hash;
		HCRYPTKEY		key;
	public:
		/*
		md5(crypt::ARRAY *md5_array) :
			md5_elements(new crypt::ARRAY()),
			string(NULL),
			provider(NULL), key(NULL), hash(NULL),
			state_ok(true) 
		{
			for (crypt::ARRAY::const_iterator i = md5_array->begin();
				i != md5_array->end();
				i++)
			{
				this->md5_elements->push_back(*i);
			}
		}
		*/

		md5(str_string *md5_string) :
			string(md5_string),
			provider(NULL), key(NULL), hash(NULL),
			state_ok(false)
		{
			//md5_elements.reserve(crypt::md5_length);
			md5_elements = string->convert_to_byte_vector(string->to_lpstr());
			if (md5_elements == NULL || md5_elements->size() != md5_length) {
				return;
			}

			state_ok = true;
		}

		md5(std::vector<BYTE> *hash_array) :
			string(NULL),
			md5_elements(new crypt::ARRAY()),
			provider(NULL), key(NULL), hash(NULL),
			state_ok(false)
		{
			if (hash_array->size() != md5_length) {
				return;
			}

			for (crypt::ARRAY::const_iterator i = hash_array->begin();
				i != hash_array->end();
				i++)
			{
				this->md5_elements->push_back(*i);
			} 

			state_ok = true;
		}

		md5(__in const BYTE *md5_sum, __in const UINT array_size) :
			string(NULL),
			md5_elements(new crypt::ARRAY()),
			provider(NULL), key(NULL), hash(NULL),
			state_ok(false)
		{
			for (UINT i = 0; i < md5_length; i++) {
				md5_elements->push_back(md5_sum[i]);
			}

			this->state_ok = true;
		}

		md5(__in const LPVOID buffer, __in const UINT buffer_size) :
			string(NULL),
			md5_elements(NULL),
			raw_buffer(buffer),
			raw_buffer_size(buffer_size)
		{
			md5_elements = crypt::generate_md5(buffer, buffer_size, &this->hash,
				&this->key, &this->provider);
			if (this->md5_elements == NULL) {
				return;
			}

			state_ok = true;
		}

		md5(__in const mem::buffer2 *raw_data) :
			string(NULL),
			md5_elements(NULL),
			raw_buffer(NULL),
			raw_buffer_size(0)
		{
			raw_data->get_raw_data(&this->raw_buffer, &this->raw_buffer_size);
			this->md5_elements = crypt::generate_md5(this->raw_buffer, this->raw_buffer_size, 
				&this->hash, &this->key, &this->provider);			
			if (this->md5_elements == NULL) {
				return;
			}

			state_ok = true;
		}

		md5(__in const mem::buffer2& raw_data) :
			string(NULL),
			md5_elements(NULL),
			raw_buffer(NULL),
			raw_buffer_size(0)
		{
			raw_data.get_raw_data(&this->raw_buffer, &this->raw_buffer_size);
			this->md5_elements = crypt::generate_md5(this->raw_buffer, this->raw_buffer_size,
				&this->hash, &this->key, &this->provider);
			if (this->md5_elements == NULL) {
				return;
			}

			state_ok = true;
		}

		md5(__in const crypt::md5& key) :
			string(NULL),
			md5_elements(NULL),
			raw_buffer(mem::malloc(md5_length)),
			raw_buffer_size(md5_length)
		{
			mem::copy(this->raw_buffer, key.get_raw_buffer(), raw_buffer_size);
			this->md5_elements = crypt::generate_md5(this->raw_buffer, this->raw_buffer_size,
				&this->hash, &this->key, &this->provider);
			if (this->md5_elements == NULL) {
				return;
			}

			state_ok = true;
		}

		~md5(VOID)
		{
			CHECK_DELETE(string);
			CHECK_DELETE(md5_elements);

			if (this->hash != 0) {
				CryptDestroyHash(this->hash);
				this->hash = 0;
			}

			if (this->key != 0) {
				CryptDestroyKey(this->key);
				this->key = 0;
			}

			/*
			if (this->provider != 0) {
				CryptReleaseContext(this->provider, 0);
				this->provider = 0;
			}
			*/
		}

		// Generates an md5 string
	private:  
		void generate_md5_string(void);

	public:
		//Returns an md5 string
		const str_string& get_md5_string(void);

		LPBYTE get_raw_buffer(void) const
		{
			return (LPBYTE)this->raw_buffer;
		}

		bool is_ok(void) const
		{
			return this->state_ok;
		}

		crypt::ARRAY *md5::get_array(void) const
		{
			return this->md5_elements;
		}

		UINT get_size_of_key(void) const
		{
			return md5_length;
		}

		// Comparison operator
		bool md5::operator==(const crypt::md5 &other) const
		{
			for (UINT i = 0; i < md5_elements->size(); i++) {
				if (this->md5_elements->at(i) != other.get_array()->at(i)) {
					return false;
				}
			}

			return true;
		}

		HCRYPTKEY get_crypt_key(void) const
		{
			return this->key;
		}

		HCRYPTHASH get_crypt_hash(void) const
		{
			return this->hash;
		}

		/*
	private: bool initialize_cryptographic_provider(void) const
		{
			if (crypt::crypt_provider == 0) {
				BOOL aquire_status = CryptAcquireContextA(
					&crypt::crypt_provider,
					NULL,
					NULL,
					PROV_RSA_FULL,
					CRYPT_VERIFYCONTEXT);
				if (aquire_status == false) {
					return false;
				}
			}
		}
		*/

	};

	// Generate a random buffer
	typedef DWORD GEN_ERROR;
	enum {
		ER_OK,
		ER_FAIL
	};
	GEN_ERROR generate_random_buffer(__inout LPVOID *out, __in const UINT size);
	class rand_buffer {
	private:
		UINT					buffer_size;
		PBYTE					buffer;

		Ptr<std::vector<BYTE>>	ByteArray;

	public:
		rand_buffer(__in const UINT size) :
			buffer_size(size),
			ByteArray(new std::vector<BYTE>),
			buffer(NULL)
		{
			GEN_ERROR gen_status = generate_random_buffer((LPVOID *)&buffer, size);
			if (gen_status != ER_OK) return;

			for (UINT i = 0; i < size; i++) ByteArray->push_back(*(PBYTE)&buffer[i]);
			mem::free_and_null((LPVOID *)&buffer);
		}

		~rand_buffer()
		{

		}

		std::vector<BYTE> *rand_buffer::get_array(VOID) const
		{

			return this->ByteArray.get_value();
		}

		/*
		PBYTE rand_buffer::get_buffer(VOID) const
		{
			return this->buffer;
		}*/

		BYTE rand_buffer::get_byte(__in const UINT position) const
		{
			if (position > buffer_size) return 0x00;

			return ByteArray->at(position);
		}

		UINT rand_buffer::get_size(VOID) const
		{
			return this->buffer_size;
		}

		// Operators
		/*
		bool rand_buffer::operator==(__in rand_buffer& other) const
		{
			if (this->buffer_size != other.get_size()) return false;

			for (UINT i = 0; i < this->buffer_size; i++) {
				if (*(PBYTE)&this->buffer[i] != other.get_byte(i)) return false;
			}

			return true;
		}*/
	};

	// Encrypt a mem::buffer2 using xor-shift. Does not xor NULL bytes. Uses MD5 as the xor key
	typedef DWORD ENCRYPT_MODE;
	enum {
		ENCRYPT_MODE_ENCRYPT,
		ENCRYPT_MODE_DECRYPT
	};
	class encrypt_xor_shift_md5;
	mem::buffer2 *encrypt_xor_shift(__in crypt::md5 const& key, __in mem::buffer2 const& raw_data, 
		__in const ENCRYPT_MODE mode);
	static const UINT crypt_channel_timeout = CRYPT_CHANNEL_TIMEOUT;
	
	class encrypt_xor_shift_md5 {
	private:
		Buffer2		EncryptedBuffer;

		bool				is_ok;

	public:
		encrypt_xor_shift_md5(__in crypt::md5 const& key, __in mem::buffer2 const& data, 
			__in const ENCRYPT_MODE mode) :
		
			EncryptedBuffer(crypt::encrypt_xor_shift(key, data, mode)),
			is_ok(false)
		{
			if (EncryptedBuffer->get_raw_size() == 0) {
				return;
			}

			this->is_ok = true;
		}

		~encrypt_xor_shift_md5(VOID)
		{

		}
										
		mem::buffer2 *get_encrypted_buffer(VOID)
		{
			if (this->is_ok == false) {
				return NULL;
			}

			return this->EncryptedBuffer.get_value();
		}

		bool get_is_ok(VOID) const
		{
			return this->is_ok;
		}
	};	

	// Encryption channel to use with sockets
	class channel;
	static const DWORD channel_seed = ENCRYPTION_CHANNEL_SEED;
	static const CHAR channel_response_ok[] = { 'O', 'K' };

	class channel {
	protected:
		Ptr<md5> Key;

		typedef struct key_request {
			UINT hostname_len;
			CHAR hostname[MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR];	   

			key_request(void)
			{
				hostname_len = 0;
				mem::zeromem(hostname, MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR);
			}
		} KEY_REQUEST, *PKEY_REQUEST;
		PKEY_REQUEST request;
		
	public:
		virtual bool process_initial(__inout SOCKET *current_socket) = 0;
		
		virtual ~channel(void) = 0;	

		// Allocates an md5 structure used for a key
		md5 *get_key(__in const str_string& host_name, __in const DWORD seed);

		// Called by socket_data; transparent to caller
	public: mem::buffer2 *decrypt(__in const mem::buffer2& encrypted_buffer) const;
	public: mem::buffer2 *encrypt(__in const mem::buffer2& decrypted_buffer) const;

	protected:
		// Creates a decrypted buffer
		mem::buffer2 *get_decrypted_buffer(__in const mem::buffer2& encrypted_buffer,
										   __in const HCRYPTKEY key) const;

		// Creates an encrypted buffer
		mem::buffer2 *get_encrypted_buffer(	__in const mem::buffer2& decrypted_buffer,
										    __in const HCRYPTKEY key) const;
	};

	class channel_client : public channel {
	private:
		StrString Hostname;

		str_string *get_host_name(void) const;

		SOCKET *client_socket;

		bool connected_to_server;

	public:
		channel_client::channel_client(__in SOCKET *current_connection);

		inline ~channel_client(void)
		{

		}

		// Sends the request
		virtual bool process_initial(__inout SOCKET *current_socket);
	};
	
	class channel_server : public channel {
		StrString RemoteHostname;

		SOCKET *server_socket;

		bool connected_to_client;
	public:
		channel_server::channel_server(__in SOCKET *current_connection);

		inline ~channel_server(void)
		{
			
		}

		// Receives the requets
		virtual bool process_initial(__inout SOCKET *current_socket);
	};

	// Standard encryption/decryption mechanism using md5 as key
	class encryption_buffer;

	class encryption_buffer {

	private:

		Ptr<md5> Key;
		Buffer2 EncryptedData, DecryptedData;

		bool is_encrypted;

	public:
		encryption_buffer::encryption_buffer(__in const crypt::md5& key, 
			__in const mem::buffer2& data,
			__in const bool is_encrypted);

		 bool encrypt(void);
		 bool decrypt(void);

		 mem::buffer2 *get_encrypted_data(void) const
		 {
			return this->EncryptedData.get_value();
		 }

		 mem::buffer2 *get_decrypted_data(void) const
		 {
			 return this->DecryptedData.get_value();
		 }

		 const crypt::md5 *get_key(void) const
		 {
			return this->Key.get_value();
		 }			  

		 const mem::buffer2 *get_decompressed_buffer(void) const
		 {
			return this->DecryptedData.get_value();
		 }

	};
};