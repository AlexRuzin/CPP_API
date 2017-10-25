#include <Windows.h>

#include <stdio.h>
#include <iostream>

#include "db.h"

#include "common/mem.h"
#include "common/str.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

using namespace db;	

#pragma comment(lib, "C:\\Program Files (x86)\\MySQL\\MySQL Connector C++ 1.1.3\\lib\\opt\\mysqlcppconn.lib")

connection_instance::connection_instance(
	__in const str_string& address,
	__in const WORD port,
	__in const str_string& database_name,
	__in const str_string& user_name,
	__in const str_string& user_pass)
{
	this->Database			= new str_string(*database_name);
	this->User				= new str_string(*user_name);
	this->Pass				= new str_string(*user_pass);

	this->ConnectionData	= new str_string("tcp://");
	this->ConnectionData	= *this->ConnectionData + address;
	LPSTR port_string		= str::int_to_stringA(port);
	StrString PortString	= new str_string(port_string);
	this->ConnectionData	= *this->ConnectionData + ":";
	this->ConnectionData	= *this->ConnectionData + **PortString;
	mem::free(port_string);

	this->sql_prepared_statements	= new std::vector<sql::PreparedStatement *>;
	this->sql_result_sets			= new std::vector<sql::ResultSet *>;
	//this->sql_pairings				= new std::map<sql::PreparedStatement *, sql::ResultSet *>;

}

bool connection_instance::connect(void)
{
	try {
		this->sql_driver		= get_driver_instance();
		this->sql_connection	= this->sql_driver->connect(**this->ConnectionData, **this->User, **this->Pass);
		this->sql_connection->setAutoCommit(false);
		this->sql_connection->setSchema(**this->Database);

		return true;
	} catch (sql::SQLException &exception) {

#ifdef DEBUG_OUT
		DBGOUT("[!] Failure in connecting to database (%s).", **this->ConnectionData);
#endif	
		return false;
	}

	return true;
}

bool connection_instance::insert(__in const str_string& statement)
{
	try {
		sql::Statement	*sql_statement = this->sql_connection->createStatement();
		sql::ResultSet *sql_result = sql_statement->executeQuery(statement.to_lpstr());

		return true;
	} catch (sql::SQLException &exception) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failure in INSERT statement\n");
#endif
		return false;
	}
	//this->sql_prepared_statements->push_back(sql_statement);
	//this->sql_result_sets->push_back(sql_result);
	//this->sql_pairings[(int)sql_statement] = sql_result;

	return true;
}

UINT connection_instance::get_count(__in const str_string& table) const
{
	StrString StatementRaw = new str_string("SELECT COUNT(*) AS _returncount FROM ");
	StatementRaw = *StatementRaw + *table;

	try{ 
		sql::Statement *sql_statement = this->sql_connection->createStatement();
		sql::ResultSet *sql_result = sql_statement->executeQuery(**StatementRaw);
		sql_result->next();
		UINT count_value = sql_result->getInt("_returncount");	   		

		return 0;
	} catch (sql::SQLException &exception) {
#ifdef DEBUG_OUT
		DBGOUT("[!] Failed in COUNT statement\n");
#endif
		return 0;
	}
}