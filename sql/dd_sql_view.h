#ifndef DD_SQL_VIEW_INCLUDED
#define DD_SQL_VIEW_INCLUDED
/* Copyright (c) 2016, 2025, Oracle and/or its affiliates.

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

#include "mysql/components/services/bits/psi_bits.h"
#include "prealloced_array.h"

class THD;
class sp_name;
class Table_ref;

/**
  Guard class which allows to invalidate TDC entries for specific tables/views.

  We use it to get rid of TABLE_SHARE objects corresponding to tables/views
  which definitions are not committed yet (and possibly won't be!).
*/

class Uncommitted_tables_guard {
 public:
  Uncommitted_tables_guard(THD *thd)
      : m_thd(thd), m_uncommitted_tables(PSI_INSTRUMENT_ME) {}
  ~Uncommitted_tables_guard();

  void add_table(Table_ref *table) { m_uncommitted_tables.push_back(table); }

 private:
  THD *m_thd;
  Prealloced_array<Table_ref *, 1> m_uncommitted_tables;
};

/**
  Update metadata of views referencing the table.

  @param          thd                 Thread handle.
  @param          db_name             Database name.
  @param          table_name          Update metadata of views referencing
                                      this table.
  @param          commit_dd_changes   Indicates whether changes to DD need
                                      to be committed.
  @param[in,out]  uncommitted_tables  Helper class to store list of views
                                      which shares need to be removed from
                                      TDC if we fail to commit changes to
                                      DD. Only used if commit_dd_changes
                                      is false.

  @note In case when commit_dd_changes is false, the caller must rollback
        both statement and transaction on failure, before any further
        accesses to DD. This is because such a failure might be caused by
        a deadlock, which requires rollback before any other operations on
        SE (including reads using attachable transactions) can be done.
        If case when commit_dd_changes is true this function will handle
        transaction rollback itself.

  @retval     false                   Success.
  @retval     true                    Failure.
*/

bool update_referencing_views_metadata(
    THD *thd, const char *db_name, const char *table_name,
    bool commit_dd_changes, Uncommitted_tables_guard *uncommitted_tables);

/**
  Update metadata of views referencing the table.

  @param          thd                 Thread handle.
  @param          table               Update metadata of views referencing
                                      this table.
  @param          commit_dd_changes   Indicates whether changes to DD need
                                      to be committed.
  @param[in,out]  uncommitted_tables  Helper class to store list of views
                                      which shares need to be removed from
                                      TDC if we fail to commit changes to
                                      DD. Only used if commit_dd_changes
                                      is false.

  @note In case when commit_dd_changes is false, the caller must rollback
        both statement and transaction on failure, before any further
        accesses to DD. This is because such a failure might be caused by
        a deadlock, which requires rollback before any other operations on
        SE (including reads using attachable transactions) can be done.
        If case when commit_dd_changes is true this function will handle
        transaction rollback itself.

  @retval     false                   Success.
  @retval     true                    Failure.
*/

bool update_referencing_views_metadata(
    THD *thd, const Table_ref *table, bool commit_dd_changes,
    Uncommitted_tables_guard *uncommitted_tables);

/**
  Update metadata of views referencing "table" being renamed and views
  referencing (if there any) new table name "new_db.new_table_name".

  @param          thd                 Thread handle.
  @param          table               Update metadata of views referencing this
                                      table.
  @param          new_db              New db name set in the rename operation.
  @param          new_table_name      New table name set in the rename
  @param          commit_dd_changes   Indicates whether changes to DD need
                                      to be committed.
  @param[in,out]  uncommitted_tables  Helper class to store list of views
                                      which shares need to be removed from
                                      TDC if we fail to commit changes to
                                      DD. Only used if commit_dd_changes
                                      is false.

  @note In case when commit_dd_changes is false, the caller must rollback
        both statement and transaction on failure, before any further
        accesses to DD. This is because such a failure might be caused by
        a deadlock, which requires rollback before any other operations on
        SE (including reads using attachable transactions) can be done.
        If case when commit_dd_changes is true this function will handle
        transaction rollback itself.
                                      operation.

  @retval     false                   Success.
  @retval     true                    Failure.
*/

bool update_referencing_views_metadata(
    THD *thd, const Table_ref *table, const char *new_db,
    const char *new_table_name, bool commit_dd_changes,
    Uncommitted_tables_guard *uncommitted_tables);

/**
  Method to update metadata of views using stored function.

  @param      thd        Thread handle.
  @param      spname     Name of the stored function.

  @retval     false      Success.
  @retval     true       Failure.
*/

bool update_referencing_views_metadata(THD *thd, const sp_name *spname);

/**
  Mark views referencing the table as invalid.

  @param          thd                 Thread handle.
  @param          table               Views referencing this table need
                                      to be marked as invalid.
  @param          skip_same_db        Indicates whether it is OK to skip
                                      views belonging to the same database
                                      as table (as they will be dropped
                                      anyway).
  @param          commit_dd_changes   Indicates whether changes to DD need
                                      to be committed.
  @param          mem_root            Memory root for allocation of temporary
                                      objects which will be cleared after
                                      each call to this function.

  @note In case when commit_dd_changes is false, the caller must rollback
        both statement and transaction on failure, before any further
        accesses to DD. This is because such a failure might be caused by
        a deadlock, which requires rollback before any other operations on
        SE (including reads using attachable transactions) can be done.
        If case when commit_dd_changes is true this function will handle
        transaction rollback itself.

  @note This call is a version of update_referencing_views_metadata(),
        which is optimized for DROP DATABASE case.


  @retval     false                   Success.
  @retval     true                    Failure.
*/

bool mark_referencing_views_invalid(THD *thd, const Table_ref *table,
                                    bool skip_same_db, bool commit_dd_changes,
                                    MEM_ROOT *mem_root);

/**
  Mark views using stored function as invalid.

  @param      thd        Thread handle.
  @param      spname     Name of the stored function.
  @param      mem_root   Memory root for allocation of temporary objects
                         which will be cleared after each call to this
                         function.

  @note This call is a version of update_referencing_views_metadata(),
        which is optimized for DROP DATABASE case.

  @retval     false      Success.
  @retval     true       Failure.
*/

bool mark_referencing_views_invalid(THD *thd, const sp_name *spname,
                                    MEM_ROOT *mem_root);

/**
  Push error or warnings in case a view is invalid and return
  the error message to the caller.

  @param        thd            Thread handle.
  @param        db             Database name.
  @param        view_name      View name.

  returns The error/warning message string.
*/
std::string push_view_warning_or_error(THD *thd, const char *db,
                                       const char *view_name);

#endif  // DD_SQL_VIEW_INCLUDED
