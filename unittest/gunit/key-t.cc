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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <gtest/gtest.h>

#include "sql/key.h"  // KEY

namespace key_unittest {

/**
  Test the API for setting and getting in-memory estimates.
*/

TEST(KeyInMemoryEstimate, InMemoryEstimateAPI) {
  KEY key;

  /*
    Test setting to not initialized.
  */
  key.set_in_memory_estimate(IN_MEMORY_ESTIMATE_UNKNOWN);
  EXPECT_EQ(key.in_memory_estimate(), IN_MEMORY_ESTIMATE_UNKNOWN);

  /*
    Test setting to lowest valid value.
  */
  key.set_in_memory_estimate(0.0);
  EXPECT_EQ(key.in_memory_estimate(), 0.0);

  /*
    Test setting to highest valid value.
  */
  key.set_in_memory_estimate(1.0);
  EXPECT_EQ(key.in_memory_estimate(), 1.0);

  /*
    Test setting to 50%.
  */
  key.set_in_memory_estimate(0.5);
  EXPECT_EQ(key.in_memory_estimate(), 0.5);
}

}  // namespace key_unittest
