#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "URL: Loading standard memory module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "URL: Loading standard memory module (32)")
#endif
#endif

#include "common/str.h"
#include "common/mem.h"

//http://www.ollydbg.de/odbg110.zip

namespace url_library {
	// Constants
	static const LPSTR _http_protocol	= "http://";
	static const LPSTR _xtp_protocol	= "xtp://";
	static const CHAR _slash			= '/';

	class url {
	private:
		Ptr<str_string>			RawURL;
		Ptr<str_string>			Hostname;
		Ptr<str_string>			File;

		enum url_type {
			TYPE_NONE,
			TYPE_HTTP,
			TYPE_XTP
		};
		url_type type;

		bool					is_ok;
	public:
		url(__in const LPSTR raw_url) :
			RawURL(new str_string(raw_url)),
			Hostname(NULL), File(NULL),
			type(TYPE_NONE),
			is_ok(false)
		{
			if (!str::compareA(raw_url, _http_protocol, str::lenA(_http_protocol))) {
				// Parse URL http
				PCHAR ptr;
				if (RawURL->lenA() < str::lenA(_http_protocol)) {
					ptr = (PCHAR)RawURL->to_lpstr();
				} else if (!mem::compare((LPCVOID)RawURL->to_lpstr(), _http_protocol, str::lenA(_http_protocol))) {
					ptr = (PCHAR)((DWORD_PTR)RawURL->to_lpstr() + str::lenA(_http_protocol));
				} else {
					ptr = (PCHAR)RawURL->to_lpstr();
				}

				// Check if there is a file
				if (str::find_character_in_stringA(ptr, str::lenA(ptr), _slash) == false || 
					*(PCHAR)&ptr[str::lenA(ptr)] == _slash) {
					// No file
					Hostname = new str_string(ptr);
					this->is_ok = true;
					return;
				}

				// There is a file
				PCHAR ptr2;
				str::find_sequence_pointerA(ptr, str::lenA(ptr), &_slash, str::ASCII_CHAR, (LPSTR *)&ptr2);
				LPSTR raw_hostname = (LPSTR)mem::malloc((UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr) + str::ASCII_CHAR);
				mem::copy(raw_hostname, ptr, (DWORD_PTR)ptr2 - (DWORD_PTR)ptr);
				this->Hostname = new str_string(raw_hostname);
				mem::free(raw_hostname);

				ptr2++;
				this->File = new str_string((LPSTR)ptr2);
				this->is_ok = true;
				this->type = TYPE_HTTP;
			} else if (!str::compareA(raw_url, _xtp_protocol, str::lenA(_xtp_protocol))) {
				// XTP protocol URL
				PCHAR ptr;
				if (RawURL->lenA() < str::lenA(_xtp_protocol)) {
					ptr = (PCHAR)RawURL->to_lpstr();
				} else if (!mem::compare((LPCVOID)RawURL->to_lpstr(), _xtp_protocol, str::lenA(_xtp_protocol))) {
					ptr = (PCHAR)((DWORD_PTR)RawURL->to_lpstr() + str::lenA(_xtp_protocol));
				} else {
					ptr = (PCHAR)RawURL->to_lpstr();
				}

				// Check if there is a file
				if (str::find_character_in_stringA(ptr, str::lenA(ptr), _slash) == false || 
					*(PCHAR)&ptr[str::lenA(ptr)] == _slash) {
					// No file
					Hostname = new str_string(ptr);
					this->is_ok = true;
					return;
				}

				// There is a file
				PCHAR ptr2;
				str::find_sequence_pointerA(ptr, str::lenA(ptr), &_slash, str::ASCII_CHAR, (LPSTR *)&ptr2);
				LPSTR raw_hostname = (LPSTR)mem::malloc((UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr) + str::ASCII_CHAR);
				mem::copy(raw_hostname, ptr, (DWORD_PTR)ptr2 - (DWORD_PTR)ptr);
				this->Hostname = new str_string(raw_hostname);
				mem::free(raw_hostname);

				ptr2++;
				this->File = new str_string((LPSTR)ptr2);
				this->type = TYPE_XTP;
				this->is_ok = true;
			} else {
				return;
			}
		}

		url(__in const str_string& raw_url) :
			RawURL(new str_string(raw_url.to_lpstr())),
			Hostname(NULL), File(NULL),
			type(TYPE_HTTP),
			is_ok(false)
		{
			if (!str::compareA(*raw_url, _http_protocol, str::lenA(_http_protocol))) {

				// Parse URL http
				PCHAR ptr;
				if (RawURL->lenA() < str::lenA(_http_protocol)) {
					ptr = (PCHAR)RawURL->to_lpstr();
				} else if (!mem::compare((LPCVOID)RawURL->to_lpstr(), _http_protocol, str::lenA(_http_protocol))) {
					ptr = (PCHAR)((DWORD_PTR)RawURL->to_lpstr() + str::lenA(_http_protocol));
				} else {
					ptr = (PCHAR)RawURL->to_lpstr();
				}

				// Check if there is a file
				if (str::find_character_in_stringA(ptr, str::lenA(ptr), _slash) == false || 
					*(PCHAR)&ptr[str::lenA(ptr)] == _slash) {
					// No file
					Hostname = new str_string(ptr);
					this->is_ok = true;
					return;
				}

				// There is a file
				PCHAR ptr2;
				str::find_sequence_pointerA(ptr, str::lenA(ptr), &_slash, str::ASCII_CHAR, (LPSTR *)&ptr2);
				LPSTR raw_hostname = (LPSTR)mem::malloc((UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr) + str::ASCII_CHAR);
				mem::copy(raw_hostname, ptr, (DWORD_PTR)ptr2 - (DWORD_PTR)ptr);
				this->Hostname = new str_string(raw_hostname);
				mem::free(raw_hostname);

				ptr2++;
				this->File = new str_string((LPSTR)ptr2);
				this->type = TYPE_HTTP;
				this->is_ok = true;
			} else if (!str::compareA(*raw_url, _xtp_protocol, str::lenA(_xtp_protocol))) {

				// XTP protocol URL
				PCHAR ptr;
				if (RawURL->lenA() < str::lenA(_xtp_protocol)) {
					ptr = (PCHAR)RawURL->to_lpstr();
				} else if (!mem::compare((LPCVOID)RawURL->to_lpstr(), _xtp_protocol, str::lenA(_xtp_protocol))) {
					ptr = (PCHAR)((DWORD_PTR)RawURL->to_lpstr() + str::lenA(_xtp_protocol));
				} else {
					ptr = (PCHAR)RawURL->to_lpstr();
				}

				// Check if there is a file
				if (str::find_character_in_stringA(ptr, str::lenA(ptr), _slash) == false || 
					*(PCHAR)&ptr[str::lenA(ptr)] == _slash) {
					// No file
					Hostname = new str_string(ptr);
					this->is_ok = true;
					return;
				}

				// There is a file
				PCHAR ptr2;
				str::find_sequence_pointerA(ptr, str::lenA(ptr), &_slash, str::ASCII_CHAR, (LPSTR *)&ptr2);
				LPSTR raw_hostname = (LPSTR)mem::malloc((UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr) + str::ASCII_CHAR);
				mem::copy(raw_hostname, ptr, (DWORD_PTR)ptr2 - (DWORD_PTR)ptr);
				this->Hostname = new str_string(raw_hostname);
				mem::free(raw_hostname);

				ptr2++;
				this->File = new str_string((LPSTR)ptr2);
				this->type = TYPE_XTP;
				this->is_ok = true;
			} else {
				return;
			}
		}

		~url(VOID)
		{

		}

		str_string *url::get_url(VOID) const
		{
			return this->RawURL.get_value();
		}

		str_string *url::get_hostname(void) const
		{
			PCHAR ptr = (PCHAR)**this->RawURL;
			for (UINT i = 0; i < this->RawURL->lenA(); i++) {
				if (ptr[i] == '/' && *(PCHAR)&ptr[i + str::ASCII_CHAR] == '/') {
					ptr = (PCHAR)&ptr[i + 2];
				}
			}

			// Compute up to file name
			PCHAR ptr2 = (PCHAR)ptr;
			for (UINT i = 0; i < str::lenA(ptr); i++) {
				if (ptr2[i] == '/') {
					ptr2 += i;
					break;
				}
			}

			LPSTR new_buffer = (LPSTR)mem::malloc((DWORD_PTR)ptr2 - (DWORD_PTR)ptr + str::ASCII_CHAR);
			mem::copy(new_buffer, ptr, (UINT)((DWORD_PTR)ptr2 - (DWORD_PTR)ptr));

			return new str_string(new_buffer);
		}

		str_string *url::get_filename(void) const
		{
			PCHAR ptr = (PCHAR)**this->RawURL;
			for (UINT i = 0; i < this->RawURL->lenA(); i++) {
				if (ptr[i] == '/' && *(PCHAR)&ptr[i + str::ASCII_CHAR]) {
					ptr = (PCHAR)&ptr[i + 2];
				}
			}

			// Compute up to file name
			for (UINT i = 0; i < str::lenA(ptr); i++) {
				if (ptr[i] == '/') {
					ptr = &ptr[i + str::ASCII_CHAR];
				}
			}

			return new str_string(ptr);
		}

		LPSTR get_raw_url(VOID) const
		{
			return this->RawURL->to_lpstr();
		}

		bool get_is_ok(VOID) const
		{
			return this->is_ok;
		}

		bool get_is_xtp(void) const
		{
			if (this->type == TYPE_XTP) {
				return true;
			}

			return false;
		}

		bool get_is_http(void) const
		{
			if (this->type == TYPE_HTTP) {
				return true;
			}

			return false;
		}
	};
};