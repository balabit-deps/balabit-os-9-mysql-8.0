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

#ifndef DD_SYSTEM_VIEWS__KEY_COLUMN_USAGE_INCLUDED
#define DD_SYSTEM_VIEWS__KEY_COLUMN_USAGE_INCLUDED

#include "sql/dd/impl/system_views/system_view_definition_impl.h"
#include "sql/dd/impl/system_views/system_view_impl.h"
#include "sql/dd/string_type.h"

namespace dd {
namespace system_views {

/*
  The class representing INFORMATION_SCHEMA.KEY_COLUMN_USAGE system view
  definition.
*/
class Key_column_usage
    : public System_view_impl<System_view_select_definition_impl> {
 public:
  enum enum_fields {
    FIELD_CONSTRAINT_CATALOG,
    FIELD_CONSTRAINT_SCHEMA,
    FIELD_CONSTRAINT_NAME,
    FIELD_TABLE_CATALOG,
    FIELD_TABLE_SCHEMA,
    FIELD_TABLE_NAME,
    FIELD_COLUMN_NAME,
    FIELD_ORDINAL_POSITION,
    FIELD_POSITION_IN_UNIQUE_CONSTRAINT,
    FIELD_REFERENCED_TABLE_SCHEMA,
    FIELD_REFERENCED_TABLE_NAME,
    FIELD_REFERENCED_COLUMN_NAME
  };

  Key_column_usage();

  static const Key_column_usage &instance();

  static const String_type &view_name() {
    static String_type s_view_name("KEY_COLUMN_USAGE");
    return s_view_name;
  }

  const String_type &name() const override {
    return Key_column_usage::view_name();
  }
};

}  // namespace system_views
}  // namespace dd

#endif  // DD_SYSTEM_VIEWS__KEY_COLUMN_USAGE_INCLUDED
