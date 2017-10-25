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

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "net/socket.h"

#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "ssl: Using OpenSSL 1.0.1g (64)")
#else 
#pragma message (OUTPUT_PRIMARY "ssl: Using OpenSSL 1.0.1g (32)")
#endif

namespace ssl {

	// Initialze SSL
	bool init(types::DEFAULT_NO_PARAMETERS);

	// SSL Channel class
	class channel;

	class channel {
	private:
		socket_tools::socket_data	*current_socket;

		bool						is_ok;
	public:
		channel(__in socket_tools::socket_data *server_socket) :
			current_socket(server_socket),
			is_ok(false)
		{

		}
	};
}