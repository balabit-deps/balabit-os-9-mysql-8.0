/* Copyright (c) 2015, 2025, Oracle and/or its affiliates.

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

#include <gtest/gtest.h>

#include "unittest/gunit/parsertest.h"
#include "unittest/gunit/test_utils.h"

namespace subquery_syntax_unittest {

using my_testing::Mock_error_handler;
using my_testing::Server_initializer;

class SubquerySyntaxTest : public ParserTest {};

TEST_F(SubquerySyntaxTest, Outer) {
  Query_block *term = parse("SET @v = ( SELECT 1 )");
  Query_expression *top_union = term->master_query_expression();
  EXPECT_EQ(nullptr, top_union->outer_query_block());
}

}  // namespace subquery_syntax_unittest
