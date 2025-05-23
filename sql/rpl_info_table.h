/* Copyright (c) 2010, 2025, Oracle and/or its affiliates.

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

#ifndef RPL_INFO_TABLE_H
#define RPL_INFO_TABLE_H

#include <stddef.h>
#include <sys/types.h>

#include "lex_string.h"
#include "my_inttypes.h"
#include "sql/rpl_info_handler.h"  // Rpl_info_handler

class Rpl_info_table_access;
class Server_ids;
struct TABLE;

/**
  Methods to find information in a table:

  FIND_SCAN does a index scan and stops at n-th occurrence.

  FIND_KEY retrieves the index entry previous populated at
  values if there is any.
*/
enum enum_find_method { FIND_SCAN, FIND_KEY };

class Rpl_info_table : public Rpl_info_handler {
  friend class Rpl_info_factory;

 public:
  ~Rpl_info_table() override;

 private:
  /**
    This property identifies the name of the schema where a
    replication table is created.
  */
  LEX_STRING str_schema;

  /**
    This property identifies the name of a replication
    table.
  */
  LEX_STRING str_table;

  /**
    This property represents a description of the repository.
    Specifically, "schema"."table".
  */
  char *description;

  /**
    This property represents the amount of fields in the repository
    primary key.
  */
  uint m_n_pk_fields;

  /**
    This property identifies the indexes of the primary keys fields
    in the table.
  */
  const uint *m_pk_field_indexes;

  /**
    This is a pointer to a class that facilitates manipulation
    of replication tables.
  */
  Rpl_info_table_access *access;

  /**
    Identifies if a table is transactional or non-transactional.
    This is used to provide a crash-safe behaviour.
  */
  bool is_transactional;

  int do_init_info() override;
  int do_init_info(uint instance) override;
  int do_init_info(enum_find_method method, uint instance);
  enum_return_check do_check_info() override;
  enum_return_check do_check_info(uint instance) override;
  void do_end_info() override;

  /**
    Flushes and syncs in-memory information into a stable storage.

    @param[in] force  If enabled ignore syncing after flushing options such as
                      relay-log-info-sync and master-info-sync and always sync

    @retval 0         Success
    @retval nonzero   Failure  This can happen if there is an error writing the
                               table, or if replica_preserve_commit_order is
                               enabled and a previous transaction has failed. In
                               both cases, the error has been reported already.
  */
  int do_flush_info(const bool force) override;
  int do_remove_info() override;
  int do_clean_info() override;
  /**
    Returns the number of entries in the table identified by:
    param_schema.param_table.

    @param[in]  nparam           Number of fields in the table.
    @param[in]  param_schema     Table's schema.
    @param[in]  param_table      Table's name.
    @param[in]  nullable_bitmap  bitmap that holds the fields that are
                                 allowed to be `NULL`-
    @param[out] counter          Number of entries found.

    @retval false Success
    @retval true  Error
  */
  static bool do_count_info(uint nparam, const char *param_schema,
                            const char *param_table,
                            MY_BITMAP const *nullable_bitmap,
                            ulonglong *counter);
  /**
    Returns if the table is being used, meaning it contains at least a
    line or some concurrency related error was returned when looking at
    the table identified by: param_schema.param_table

    @param[in]  nparam           Number of fields in the table.
    @param[in]  param_schema     Table's schema.
    @param[in]  param_table      Table's name.
    @param[in]  nullable_bitmap  bitmap that holds the fields that are
                                 allowed to be `NULL`-

    @retval a pair of booleans
            First element is true if an error occurred, false otherwise.
            Second element is true if the table is not empty or an access error
            occurred meaning someone else is accessing it. False if the table
            is empty.
  */
  static std::pair<bool, bool> table_in_use(uint nparam,
                                            const char *param_schema,
                                            const char *param_table,
                                            MY_BITMAP const *nullable_bitmap);

  static int do_reset_info(uint nparam, const char *param_schema,
                           const char *param_table, const char *channel_name,
                           MY_BITMAP const *nullable_bitmap);
  int do_prepare_info_for_read() override;
  int do_prepare_info_for_write() override;

  bool do_set_info(const int pos, const char *value) override;
  bool do_set_info(const int pos, const uchar *value,
                   const size_t size) override;
  bool do_set_info(const int pos, const int value) override;
  bool do_set_info(const int pos, const ulong value) override;
  bool do_set_info(const int pos, const float value) override;
  bool do_set_info(const int pos, const Server_ids *value) override;
  /**
    Setter needed to set nullable fields to `NULL`.

    @param pos the index of the field to set to `NULL`.
    @param value unused value, needed to desimbiguate polimorphism.

    @return true if there was an error and false otherwise.
   */
  bool do_set_info(const int pos, const std::nullptr_t value) override;
  /**
    Setter needed to set nullable fields to `NULL`.

    @param pos the index of the field to set to `NULL`.
    @param value unused value, needed to desimbiguate polimorphism.
    @param size unused value size, needed to desimbiguate polimorphism.

    @return true if there was an error and false otherwise.
   */
  bool do_set_info(const int pos, const std::nullptr_t value,
                   const size_t size) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, char *value, const size_t size,
      const char *default_value) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, uchar *value, const size_t size,
      const uchar *default_value) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, int *value, const int default_value) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, ulong *value, const ulong default_value) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, float *value, const float default_value) override;
  Rpl_info_handler::enum_field_get_status do_get_info(
      const int pos, Server_ids *value,
      const Server_ids *default_value) override;
  char *do_get_description_info() override;

  bool do_is_transactional() override;
  bool do_update_is_transactional() override;
  uint do_get_rpl_info_type() override;

  /**
    Verify if the table primary key fields are at the expected (column)
    position.

    @param table The table handle where the verification will be done.

    @return false if the table primary key fields are fine.
    @return true  if problems were found with table primary key fields.
  */
  bool verify_table_primary_key_fields(TABLE *table);

  Rpl_info_table(uint nparam, const char *param_schema, const char *param_table,
                 const uint param_n_pk_fields = 0,
                 const uint *param_pk_field_indexes = nullptr,
                 MY_BITMAP const *nullable_bitmap = nullptr);

  Rpl_info_table(const Rpl_info_table &info);
  Rpl_info_table &operator=(const Rpl_info_table &info);
};
#endif /* RPL_INFO_TABLE_H */
