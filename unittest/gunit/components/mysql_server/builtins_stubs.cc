/* Copyright (c) 2017, 2025, Oracle and/or its affiliates.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2.0,
as published by the Free Software Foundation.

This program is designed to work with certain software (including
but not limited to OpenSSL) that is licensed under separate terms,
as designated in a particular file or component or in included license
documentation.  The authors of MySQL hereby grant you an additional
permission to link the program and your derivative works with the
separately licensed software that they have either included with
the program or referenced in the documentation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License, version 2.0, for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef BUILTIN_STUBS
#define BUILTIN_STUBS

#include <mysql/components/services/log_shared.h>
#include <atomic>

#include "my_compiler.h"
#include "sql/sql_class.h"

std::atomic<int32> connection_events_loop_aborted_flag;
thread_local THD *current_thd = nullptr;
ulong log_error_verbosity;
ulong opt_log_timestamps = 0;
char *opt_log_error_services = nullptr;
const char *log_error_dest = "stderr";

void THD::debug_assert_query_locked() const {}

my_thread_id log_get_thread_id(THD *thd [[maybe_unused]]) { return -1; }

void log_write_errstream(const char *buffer [[maybe_unused]],
                         size_t length [[maybe_unused]]) {}

const char *mysql_errno_to_symbol(int mysql_errno [[maybe_unused]]) {
  return nullptr;
}

int mysql_symbol_to_errno(const char *error_symbol [[maybe_unused]]) {
  return -1;
}

const char *mysql_errno_to_sqlstate(uint mysql_errno [[maybe_unused]]) {
  return nullptr;
}

int mysql_errno_to_builtin(uint mysql_errno [[maybe_unused]]) { return 0; }

int log_vmessage(int log_type [[maybe_unused]], va_list lili [[maybe_unused]]) {
  return -1;
}

int log_message(int log_type [[maybe_unused]], ...) { return -1; }

const char *error_message_for_error_log(int mysql_errno [[maybe_unused]]) {
  return nullptr;
}

void push_warning(THD *thd [[maybe_unused]],
                  Sql_condition::enum_severity_level severity [[maybe_unused]],
                  uint code [[maybe_unused]],
                  const char *message_text [[maybe_unused]]) {}

#endif
