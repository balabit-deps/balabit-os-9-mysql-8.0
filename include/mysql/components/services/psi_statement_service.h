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

#ifndef COMPONENTS_SERVICES_PSI_STATEMENT_SERVICE_H
#define COMPONENTS_SERVICES_PSI_STATEMENT_SERVICE_H

#include <mysql/components/service.h>
#include <mysql/components/services/bits/psi_statement_bits.h>

/*
  Version 1.
  Introduced in MySQL 8.0.3
  Deprecated in MySQL 8.0.14
  Obsoleted in MySQL 8.0.31
  Status: Obsolete, use version 4 instead.
*/

/*
  Version 2.
  Introduced in MySQL 8.0.14
  Deprecated in MySQL 8.0.28
  Obsoleted in MySQL 8.0.31
  Status: Obsolete, use version 4 instead.
*/

/*
  Version 3.
  Introduced in MySQL 8.0.28
  Obsoleted in MySQL 8.0.31
  Status: Obsolete, use version 4 instead.
*/

/*
  Version 4.
  Introduced in MySQL 8.0.31
  Obsoleted in MySQL 8.0.33
  Status: Obsolete, use version 5 instead.
  Changes compared to version 3:
  - get_thread_statement_locker_v4_t,
    the state structure is bigger.
*/

/*
  Version 5.
  Introduced in MySQL 8.0.33
  Status: active.
  Changes compared to version 4:
  - get_thread_statement_locker_v5_t
    (the state structure is bigger),
    notify_statement_query_attributes_v5_t,
    statement_abort_telemetry_v5_t.
*/
BEGIN_SERVICE_DEFINITION(psi_statement_v5)
/** @sa register_statement_v1_t. */
register_statement_v1_t register_statement;
/** @sa get_thread_statement_locker_v1_t. */
get_thread_statement_locker_v5_t get_thread_statement_locker;
/** @sa refine_statement_v1_t. */
refine_statement_v1_t refine_statement;
/** @sa start_statement_v1_t. */
start_statement_v1_t start_statement;
/** @sa set_statement_text_v1_t. */
set_statement_text_v1_t set_statement_text;
/** @sa set_statement_query_id_t. */
set_statement_query_id_t set_statement_query_id;
/** @sa set_statement_lock_time_t. */
set_statement_lock_time_t set_statement_lock_time;
/** @sa set_statement_rows_sent_t. */
set_statement_rows_sent_t set_statement_rows_sent;
/** @sa set_statement_rows_examined_t. */
set_statement_rows_examined_t set_statement_rows_examined;
/** @sa inc_statement_created_tmp_disk_tables. */
inc_statement_created_tmp_disk_tables_t inc_statement_created_tmp_disk_tables;
/** @sa inc_statement_created_tmp_tables. */
inc_statement_created_tmp_tables_t inc_statement_created_tmp_tables;
/** @sa inc_statement_select_full_join. */
inc_statement_select_full_join_t inc_statement_select_full_join;
/** @sa inc_statement_select_full_range_join. */
inc_statement_select_full_range_join_t inc_statement_select_full_range_join;
/** @sa inc_statement_select_range. */
inc_statement_select_range_t inc_statement_select_range;
/** @sa inc_statement_select_range_check. */
inc_statement_select_range_check_t inc_statement_select_range_check;
/** @sa inc_statement_select_scan. */
inc_statement_select_scan_t inc_statement_select_scan;
/** @sa inc_statement_sort_merge_passes. */
inc_statement_sort_merge_passes_t inc_statement_sort_merge_passes;
/** @sa inc_statement_sort_range. */
inc_statement_sort_range_t inc_statement_sort_range;
/** @sa inc_statement_sort_rows. */
inc_statement_sort_rows_t inc_statement_sort_rows;
/** @sa inc_statement_sort_scan. */
inc_statement_sort_scan_t inc_statement_sort_scan;
/** @sa set_statement_no_index_used. */
set_statement_no_index_used_t set_statement_no_index_used;
/** @sa set_statement_no_good_index_used. */
set_statement_no_good_index_used_t set_statement_no_good_index_used;
/** @sa set_statement_secondary_engine_v3_t. */
set_statement_secondary_engine_v3_t set_statement_secondary_engine;
/** @sa end_statement_v1_t. */
end_statement_v1_t end_statement;

/** @sa create_prepared_stmt_v1_t. */
create_prepared_stmt_v1_t create_prepared_stmt;
/** @sa destroy_prepared_stmt_v1_t. */
destroy_prepared_stmt_v1_t destroy_prepared_stmt;
/** @sa reprepare_prepared_stmt_v1_t. */
reprepare_prepared_stmt_v1_t reprepare_prepared_stmt;
/** @sa execute_prepared_stmt_v1_t. */
execute_prepared_stmt_v1_t execute_prepared_stmt;
/** @sa set_prepared_stmt_text_v1_t. */
set_prepared_stmt_text_v1_t set_prepared_stmt_text;
/** @sa set_prepared_stmt_secondary_engine_v3_t */
set_prepared_stmt_secondary_engine_v3_t set_prepared_stmt_secondary_engine;

/** @sa digest_start_v1_t. */
digest_start_v1_t digest_start;
/** @sa digest_end_v1_t. */
digest_end_v1_t digest_end;

/** @sa get_sp_share_v1_t. */
get_sp_share_v1_t get_sp_share;
/** @sa release_sp_share_v1_t. */
release_sp_share_v1_t release_sp_share;
/** @sa start_sp_v1_t. */
start_sp_v1_t start_sp;
/** @sa start_sp_v1_t. */
end_sp_v1_t end_sp;
/** @sa drop_sp_v1_t. */
drop_sp_v1_t drop_sp;

notify_statement_query_attributes_v5_t notify_statement_query_attributes;
statement_abort_telemetry_v5_t statement_abort_telemetry;
END_SERVICE_DEFINITION(psi_statement_v5)

#endif /* COMPONENTS_SERVICES_PSI_STATEMENT_SERVICE_H */
