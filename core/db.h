#pragma once

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#include <vector>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "SQL Connector")
#else 
#pragma message (OUTPUT_PRIMARY "SQL Connector")
#endif
#endif

#pragma warning(disable: 4251)

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

#include "common/mem.h"
#include "common/str.h"

namespace db {

	// Connection instance class
	class connection_instance;
	typedef Ptr<connection_instance> ConnectionInstance;

	class connection_instance {
	protected:
		sql::Driver			*sql_driver;
		sql::Connection		*sql_connection;

		StrString			ConnectionData;
		StrString			Database;
		StrString			User;
		StrString			Pass;

		// Executed statement vectors
		std::vector<sql::PreparedStatement *> *sql_prepared_statements;
		std::vector<sql::ResultSet *> *sql_result_sets;
		std::map<sql::PreparedStatement *, sql::ResultSet *> *sql_pairings;

	public:
		connection_instance::connection_instance(
			__in const str_string& address,
			__in const WORD port,
			__in const str_string& database_name,
			__in const str_string& user_name,
			__in const str_string& user_pass);
		connection_instance::connection_instance(void)
		{
			delete this->sql_prepared_statements;
			delete this->sql_result_sets;
			//delete this->sql_pairings;
		}

		bool connect(void);

		// Inserts a value
		bool insert(__in const str_string& statement);

		// Get count (number of elements in a table)
		UINT get_count(__in const str_string& table) const;

		sql::Connection *get_connection(void) const
		{
			return this->sql_connection;
		}
	};


}