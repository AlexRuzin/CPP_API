#include <Windows.h>

#include "resource.h"

#include "api.h"
#include "common/mem.h"
#include "common/inline.h"

using namespace resource;

resource::instance::instance(__in const LPSTR name, __in const WORD id)
{
	this->Name						= new str_string(name);
	this->id						= id;
	this->RawData					= NULL;

	this->Handles					= new handles();

	this->current_module			= get_local_dll_base();
	if (this->current_module == NULL) {
		return;
	}

	this->Handles->resource_handle	= cFindResourceA(this->current_module, MAKEINTRESOURCE(id), this->Name->to_lpstr());
	if (this->Handles->resource_handle == NULL) {
		return;
	}

	this->Handles->global_handle	= cLoadResource(this->current_module, this->Handles->resource_handle);
	if (this->Handles->global_handle == NULL) {
		return;
	}

	//cLockResource(this->Handles->global_handle);

	this->RawData = new mem::buffer2((const LPVOID)this->Handles->global_handle, 
		cSizeofResource(this->current_module, this->Handles->resource_handle));

	return;
}

void resource::instance::add_null(types::DEFAULT_NO_PARAMETERS)
{
	this->RawData->append_null();
}