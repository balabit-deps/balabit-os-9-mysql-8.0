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

#include "client/dump/abstract_data_object.h"

using namespace Mysql::Tools::Dump;

Abstract_data_object::Abstract_data_object(uint64 id, const std::string &name,
                                           const std::string &schema)
    : m_id(id), m_schema(schema), m_name(name) {}

std::string Abstract_data_object::get_name() const { return m_name; }

std::string Abstract_data_object::get_schema() const { return m_schema; }

uint64 Abstract_data_object::get_id() const { return m_id; }

Abstract_data_object::~Abstract_data_object() = default;
