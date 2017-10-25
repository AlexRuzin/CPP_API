#pragma once
#ifndef _WINDOWS_
#include <Windows.h>
#endif
 
/*
#ifdef USE_PE32
#error "USE_PE32 already defined"
#endif
#define USE_PE32
*/

#include <stdio.h>
#include <psapi.h>

#include <vector>
#include <memory>

#ifndef CONFIG_OK
#include "../config.h"
#endif

#ifndef DISABLE_LIBRARY_INFO
#ifdef CONFIG_COMPILE64
#pragma message (OUTPUT_PRIMARY "sync: Loading standard sync module (64)")
#else 
#pragma message (OUTPUT_PRIMARY "sync: Loading standard sync module (32)")
#endif
#endif

#include "common/str.h"
#include "common/mem.h"

 namespace sync {

	 class sync {
	 protected:
		 bool object_ok;

		 bool get_is_ok(void) const
		 {
			 return this->object_ok;
		 }

	 public:
		 // Sync virtual functions
		 virtual void sync_enter(void) const = 0;
		 virtual void sync_leave(void) const = 0;
	 };

	 class mutex : public sync {

	 // Sync functions
	 public:
		 mutex::mutex(__inopt str_string *name);

		 virtual void sync_enter(void) const;
		 virtual void sync_leave(void) const;
		 
		 virtual ~mutex(void)
		 {

		 }
	 };

	 class critical_section : public sync {
	 private:
		 PCRITICAL_SECTION sync_object;

	 // Sync functions
	 public:
		 critical_section::critical_section(types::DEFAULT_NO_PARAMETERS);

		 virtual void sync_enter(void) const;
		 virtual void sync_leave(void) const;

		 virtual ~critical_section(void);	

		 PCRITICAL_SECTION get_critical_section(void) const;
	 };
 }