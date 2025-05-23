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

#ifndef DD__VIEW_ROUTINE_IMPL_INCLUDED
#define DD__VIEW_ROUTINE_IMPL_INCLUDED

#include <sys/types.h>
#include <new>

#include "sql/dd/impl/raw/raw_record.h"
#include "sql/dd/impl/types/weak_object_impl.h"  // dd::Weak_object_impl
#include "sql/dd/string_type.h"
#include "sql/dd/types/view_routine.h"  // dd::View_routine

namespace dd {

///////////////////////////////////////////////////////////////////////////

class Object_key;
class Object_table;
class Open_dictionary_tables_ctx;
class View;
class View_impl;
class Weak_object;

///////////////////////////////////////////////////////////////////////////

class View_routine_impl : public Weak_object_impl, public View_routine {
 public:
  View_routine_impl();

  View_routine_impl(View_impl *view);

  View_routine_impl(const View_routine_impl &src, View_impl *parent);

  ~View_routine_impl() override = default;

 public:
  static void register_tables(Open_dictionary_tables_ctx *otx);

  const Object_table &object_table() const override;

  bool validate() const override;

  bool store_attributes(Raw_record *r) override;

  bool restore_attributes(const Raw_record &r) override;

  void debug_print(String_type &outb) const override;

  void set_ordinal_position(uint) {}

  virtual uint ordinal_position() const { return -1; }

 public:
  /////////////////////////////////////////////////////////////////////////
  // routine catalog.
  /////////////////////////////////////////////////////////////////////////

  const String_type &routine_catalog() const override {
    return m_routine_catalog;
  }

  void set_routine_catalog(const String_type &sf_catalog) override {
    m_routine_catalog = sf_catalog;
  }

  /////////////////////////////////////////////////////////////////////////
  // routine schema.
  /////////////////////////////////////////////////////////////////////////

  const String_type &routine_schema() const override {
    return m_routine_schema;
  }

  void set_routine_schema(const String_type &sf_schema) override {
    m_routine_schema = sf_schema;
  }

  /////////////////////////////////////////////////////////////////////////
  // routine name.
  /////////////////////////////////////////////////////////////////////////

  const String_type &routine_name() const override { return m_routine_name; }

  void set_routine_name(const String_type &sf_name) override {
    m_routine_name = sf_name;
  }

  /////////////////////////////////////////////////////////////////////////
  // view.
  /////////////////////////////////////////////////////////////////////////

  const View &view() const override;

  View &view() override;

 public:
  static View_routine_impl *restore_item(View_impl *view) {
    return new (std::nothrow) View_routine_impl(view);
  }

  static View_routine_impl *clone(const View_routine_impl &other,
                                  View_impl *view) {
    return new (std::nothrow) View_routine_impl(other, view);
  }

 public:
  Object_key *create_primary_key() const override;
  bool has_new_primary_key() const override;

 private:
  String_type m_routine_catalog;
  String_type m_routine_schema;
  String_type m_routine_name;

  // References to other objects
  View_impl *m_view;
};

///////////////////////////////////////////////////////////////////////////

}  // namespace dd

#endif  // DD__VIEW_ROUTINE_IMPL_INCLUDED
