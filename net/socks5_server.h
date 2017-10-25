#include <Windows.h>

#include "debug/debug.h"

#pragma once

namespace socks5_server {

	class socks5_instance {
	private:
		// Listener port
		WORD			listen_port;

	public:
		socks5_instance(__in const WORD port) :
			listen_port(port)
		{
#ifdef DEBUG_OUT
			DBGOUT("socks5_server: Starting listener on port %d\n", port);
#endif



		}
	};
};