/*
  Copyright (c) 2015, 2025, Oracle and/or its affiliates.

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
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#include "client/dump/row_group_dump_task.h"

#include <stddef.h>

using namespace Mysql::Tools::Dump;

void Row_group_dump_task::set_completed() {
  for (std::vector<Row *>::iterator it = m_rows.begin(); it != m_rows.end();
       ++it) {
    delete *it;
    *it = NULL;
  }

  Abstract_simple_dump_task::set_completed();
}

bool Row_group_dump_task::can_be_executed() const { return true; }

I_data_object *Row_group_dump_task::get_related_db_object() const {
  return nullptr;
}

Row_group_dump_task::Row_group_dump_task(Table *source_table,
                                         const std::vector<Mysql_field> &fields,
                                         const bool has_generated_column,
                                         const bool has_invisible_columns)
    : m_source_table(source_table),
      m_fields(fields),
      m_has_generated_columns(has_generated_column),
      m_has_invisible_columns(has_invisible_columns) {}
