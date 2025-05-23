/* Copyright (c) 2014, 2025, Oracle and/or its affiliates.

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

#ifndef DD__OBJECT_TABLE_IMPL_INCLUDED
#define DD__OBJECT_TABLE_IMPL_INCLUDED

#include "sql/dd/impl/types/object_table_definition_impl.h"  // Object_table_def
#include "sql/dd/types/object_table.h"                       // Object_table

class THD;

namespace dd {

///////////////////////////////////////////////////////////////////////////

class Object_table_impl : virtual public Object_table {
 protected:
  mutable uint m_last_dd_version;
  Object_table_definition_impl m_target_def;
  mutable bool m_actual_present;
  mutable Object_table_definition_impl m_actual_def;
  bool m_hidden;

 public:
  // Enumeration of options that are used by all DD table subclasses.
  enum class Common_option {
    ENGINE,
    CHARSET,
    COLLATION,
    ROW_FORMAT,
    STATS_PERSISTENT,
    TABLESPACE
  };

  /*
    Enumeration of indexes that are used by several DD table subclasses.
    Some object keys will implicitly expect these indexes to have a
    certain predefined ordinal position. Note that the enumeration is
    the positional index of each index (starting at 0), not the ordinal
    position of the index (starting at 1).
  */
  enum class Common_index { PK_ID, UK_NAME };

  /*
    Enumeration of fields that are expected by some object keys to have
    the same ordinal position for most DD tables. The enumeration is the
    positional index of the field (starting at 0).
  */
  enum class Common_field { ID };

  /*
    Constructor used for tables required by plugins. Common options are
    not used for those.
  */
  Object_table_impl(const String_type &schema_name,
                    const String_type &table_name,
                    const String_type &ddl_statement)
      : m_last_dd_version(0),
        m_target_def(schema_name, table_name, ddl_statement),
        m_actual_present(false),
        m_actual_def(),
        m_hidden(false) {}

  /*
    Constructor used by DD table subclasses. These will all use the
    common options.
  */
  Object_table_impl();

  const String_type &name() const override {
    return m_target_def.get_table_name();
  }

  Object_table_definition_impl *target_table_definition() override {
    return (m_last_dd_version != 0 ? nullptr : &m_target_def);
  }

  const Object_table_definition_impl *target_table_definition() const override {
    return (m_last_dd_version != 0 ? nullptr : &m_target_def);
  }

  void set_abandoned(uint last_dd_version) const override {
    m_last_dd_version = last_dd_version;
  }

  bool is_abandoned() const override { return (m_last_dd_version != 0); }

  const Object_table_definition_impl *actual_table_definition() const override {
    return (m_actual_present ? &m_actual_def : nullptr);
  }

  bool set_actual_table_definition(
      const Properties &table_def_properties) const override;

  virtual int field_number(int target_field_number,
                           const String_type &field_label) const;

  int field_number(const String_type &field_label) const override;

  bool populate(THD *) const override { return false; }

  bool is_hidden() const override { return m_hidden; }

  void set_hidden(bool hidden) override { m_hidden = hidden; }

  ~Object_table_impl() override = default;
};

///////////////////////////////////////////////////////////////////////////

}  // namespace dd

#endif  // DD__OBJECT_TABLE_IMPL_INCLUDED
