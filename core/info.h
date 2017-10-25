#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <stdio.h>
#include <psapi.h>

#include <vector>
#include <memory>

#ifndef CONFIG_OK
#include "../config.h"
#endif	   

#include "common/mem.h"
#include "common/str.h"

// Test for files (PF: Program Files, AD: AppData
#define PF_TEST_BITCOIN		"\\Bitcoin\\bitcoin-qt.exe"
#define AD_TEST_BITCOIN2	"\\Roaming\\Bitcoin\\peers.dat"
#define AD_TEST_CHROME		"\\Local\\Google\\Chrome\\Application\\chrome.exe"
#define PF64_TEST_OPERA		"\\Opera\\opera.exe"	
#define PF_TEST_OPERA		"\\Opera\\opera.exe"
#define PF_TEST_FF			"\\Mozilla Firefox\\firefox.exe"
#define PF64_TEST_IE		"\\Internet Explorer\\iexplore.exe"
#define PF_TEST_IE			"\\Internet Explorer\\iexplore.exe"

namespace client_info {

	// Test constants
	static const LPSTR		pf_test_bitcoin				= PF_TEST_BITCOIN;
	static const LPSTR		ad_test_bitcoin2			= AD_TEST_BITCOIN2;
	static const LPSTR		ad_test_chrome				= AD_TEST_CHROME;
	static const LPSTR		pf64_test_opera				= PF64_TEST_OPERA;
	static const LPSTR		pf_test_opera				= PF_TEST_OPERA;
	static const LPSTR		pf_test_ff					= PF_TEST_FF;
	static const LPSTR		pf64_test_ie				= PF64_TEST_IE;
	static const LPSTR		pf_test_ie					= PF_TEST_IE;

	bool check_file_existence(__in const str_string& path);
	bool check_file_existence(__in const LPSTR path);

	class info {
	public:
		typedef struct raw_info {
			CHAR			hostname[MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR];
			UINT			hostname_len;

			bool			is_bitcoin;
			bool			is_chrome;
			bool			is_opera;
			bool			is_firefox;
			bool			is_ie;

			CHAR			bitcoin_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR			chrome_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR			opera_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR			firefox_loc[MAX_PATH + str::ASCII_CHAR];
			CHAR			ie_loc[MAX_PATH + str::ASCII_CHAR];

			SYSTEM_INFO		sys_info;
			OSVERSIONINFOA	os_info;

			raw_info(void)
			{
				mem::zeromem(hostname, sizeof(hostname));
				hostname_len	= 0;
				is_bitcoin		= false;
				is_chrome		= false;
				is_opera		= false;
				is_firefox		= false;
				is_ie			= false;

				mem::zeromem(bitcoin_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(chrome_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(opera_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(firefox_loc, MAX_PATH + str::ASCII_CHAR);
				mem::zeromem(ie_loc, MAX_PATH + str::ASCII_CHAR);

				mem::zeromem(&sys_info, sizeof(SYSTEM_INFO));
				mem::zeromem(&os_info, sizeof(OSVERSIONINFOA));
			}

		} RAW_INFO, *PRAW_INFO;

	private:
		PRAW_INFO	raw_data;

		StrString Hostname;
		OSVERSIONINFOA *version_info;
		SYSTEM_INFO *system_info;

		StrString	AppData;
		StrString	ProgFiles86;
		StrString	ProgFiles64;

	public:
		info(void);
		~info(void);

		bool gather_data(void);

		bool parse_directories(__inout raw_info *data);

		raw_info *get_data(void) const
		{
			return this->raw_data;
		}
	}; 
}
