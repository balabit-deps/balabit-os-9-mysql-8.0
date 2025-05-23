/* Copyright (c) 2020, 2025, Oracle and/or its affiliates.

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

#include <mysql/components/component_implementation.h>
#include "my_dbug.h"  // DBUG_EXECUTE_IF

/**
  This file contains a definition of the test_component_deinit.
  This component is used to test the failure case of deinit function.
*/

/**
  Initialization entry method for Component used when loading the Component.

  @return Status of performed operation
  @retval 0 success
  @retval non-zero failure
*/
mysql_service_status_t test_init() { return 0; }

/**
  De-initialization method for Component used when unloading the Component.

  @return Status of performed operation
  @retval 0 success
  @retval non-zero failure
*/
mysql_service_status_t test_deinit() {
  DBUG_EXECUTE_IF("component_deinit_function_success", return (0););
  /*
    To test error message at server SHUTDOWN time, returning failure
  */
  return 1;
}

BEGIN_COMPONENT_PROVIDES(test_component_deinit)
END_COMPONENT_PROVIDES();

/* An empty list of dependencies. */
BEGIN_COMPONENT_REQUIRES(test_component_deinit) END_COMPONENT_REQUIRES();

/* A list of metadata to describe the Component. */
BEGIN_COMPONENT_METADATA(test_component_deinit)
METADATA("mysql.author", "Oracle Corporation"),
    METADATA("mysql.license", "GPL"), METADATA("test_property", "1"),
    END_COMPONENT_METADATA();

/* Declaration of the Component. */
DECLARE_COMPONENT(test_component_deinit, "mysql:test_component_deinit")
test_init, test_deinit END_DECLARE_COMPONENT();

/* Defines list of Components contained in this library. Note that for now
  we assume that library will have exactly one Component. */
DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(test_component_deinit)
    END_DECLARE_LIBRARY_COMPONENTS
