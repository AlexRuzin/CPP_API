#include <Windows.h>
#include <stdio.h>

#include "debug/debug.h"
#include "api.h"
#include "common/mem.h"

#ifdef DEBUG_OUT/*
VOID debug::debug_print(char *FormatString, ...) 
 { 
	CHAR dbgout[1024];
	va_list   vaList;
	LPSTR output;
	//BREAK;

	mem::zeromem(dbgout, sizeof(dbgout));

	va_start(vaList, FormatString); 
	//nop;
	wvsprintfA(dbgout, FormatString, vaList); 
	//nop;
	cOutputDebugStringA(dbgout); 
	//nop;
	va_end(vaList); 
	//nop;

	return;
 }*/
VOID debug::debug_print(LPCSTR FormatString, ...)
{
	va_list args;
	va_start(args, FormatString);

	UCHAR buffer[1024];
	mem::zeromem(buffer, sizeof(buffer));

	INT buffer_count = cvsnprintfA((char *)buffer, sizeof(buffer) - 1, FormatString, args);

	cOutputDebugStringA((LPSTR)buffer);

	va_end(args);

	return;
}

#endif
/*
void XTrace(LPCTSTR lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);
	int nBuf;
	TCHAR szBuffer[512]; // get rid of this hard-coded buffer
	nBuf = _vsntprintf(szBuffer, 511, lpszFormat, args);
	::OutputDebugString(szBuffer);
	va_end(args);
}*/

/*
void FormatOutput(LPCSTR formatstring, ...) 
{
   int nSize = 0;
   char buff[10];
   memset(buff, 0, sizeof(buff));
   va_list args;
   va_start(args, formatstring);
   nSize = vsnprintf( buff, sizeof(buff) - 1, formatstring, args); // C4996
// Note: vsnprintf is deprecated; consider vsnprintf_s instead
   printf("nSize: %d, buff: %s\n", nSize, buff);
}
*/