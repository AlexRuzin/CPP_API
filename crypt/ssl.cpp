#include <Windows.h>

#include <vector>

#include "ssl.h"

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

using namespace ssl;

static bool init_status = false;
bool ssl::init(types::DEFAULT_NO_PARAMETERS)
{
	if (init_status == false) {

		SSL_load_error_strings();
		SSL_library_init();
		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();

		init_status = true;
		return true;
	}

	return true;
}