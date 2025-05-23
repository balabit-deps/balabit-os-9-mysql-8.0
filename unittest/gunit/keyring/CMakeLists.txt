# Copyright (c) 2013, 2025, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is designed to work with certain software (including
# but not limited to OpenSSL) that is licensed under separate terms,
# as designated in a particular file or component or in included license
# documentation.  The authors of MySQL hereby grant you an additional
# permission to link the program and your derivative works with the
# separately licensed software that they have either included with
# the program or referenced in the documentation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

SET(TESTS
  keyring-api
  keys_container
  buffered_file_io
  converter
  file_io
)

ADD_DEFINITIONS(-DLOG_COMPONENT_TAG="keyring_file_tests")

SET(ALL_KEYRING_TESTS)
FOREACH(test ${TESTS})
  LIST(APPEND ALL_KEYRING_TESTS ${test}-t.cc)
ENDFOREACH()


SET(SRC_FILES)
LIST(APPEND SRC_FILES
  ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_key.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_container.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_iterator.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/buffered_file_io.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/converter.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/buffer.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/hash_to_buffer_serializer.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/digest.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/file_io.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/checker/checker.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/checker/checker_factory.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/checker/checker_ver_1_0.cc
  ${CMAKE_SOURCE_DIR}/plugin/keyring/checker/checker_ver_2_0.cc
  ${CMAKE_SOURCE_DIR}/unittest/gunit/keyring/buffered_file_io_10.cc
  ${CMAKE_SOURCE_DIR}/unittest/gunit/keyring/psi_memory_key.cc
  )

IF(WIN32)
  LIST(APPEND SRC_FILES ../../../sql/nt_servc.cc)
ENDIF()

ADD_STATIC_LIBRARY(keyring_test ${SRC_FILES} LINK_LIBRARIES ext::zlib)
ADD_DEPENDENCIES(keyring_test GenError)

MYSQL_ADD_EXECUTABLE(merge_keyring_file_tests-t
  ${ALL_KEYRING_TESTS}
  ENABLE_EXPORTS
  ADD_TEST merge_keyring_file_tests)

TARGET_LINK_LIBRARIES(merge_keyring_file_tests-t
  keyring_test
  gunit_large
  server_unittest_library
  )

ADD_DEPENDENCIES(merge_keyring_file_tests-t GenError)
IF(MY_COMPILER_IS_GNU)
  MY_CHECK_CXX_COMPILER_WARNING("error=maybe-uninitialized" HAS_WARN_FLAG)
  IF(HAS_WARN_FLAG)
    MY_TARGET_LINK_OPTIONS(merge_keyring_file_tests-t "${HAS_WARN_FLAG}")
  ENDIF()
ENDIF()

FOREACH(test ${TESTS})
  MYSQL_ADD_EXECUTABLE(${test}-t ${test}-t.cc
    ENABLE_EXPORTS SKIP_INSTALL EXCLUDE_FROM_ALL)

  TARGET_LINK_LIBRARIES(${test}-t
    keyring_test
    gunit_large
    server_unittest_library
    )
ENDFOREACH()

