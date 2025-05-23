# Copyright (c) 2015, 2025, Oracle and/or its affiliates.
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

ADD_SUBDIRECTORY(src/)
IF(WITH_UNIT_TESTS)
  ADD_SUBDIRECTORY(tests/)
ENDIF()

IF(ROUTER_INSTALL_DOCDIR)
  INSTALL(FILES ${PROJECT_SOURCE_DIR}/doc/sample_mysqlrouter.conf
          DESTINATION ${ROUTER_INSTALL_DOCDIR}
          COMPONENT Router)
  # we do not install the README, License and so on as we
  # are part of the server-tree
ENDIF()


# Install logging, runtime, config and data folders
IF(INSTALL_LAYOUT STREQUAL "STANDALONE")
  FOREACH(_dirvar LOGDIR RUNTIMEDIR CONFIGDIR DATADIR)
    SET(_dir ${ROUTER_INSTALL_${_dirvar}})
    IF(NOT _dir)
      MESSAGE(FATAL_ERROR "ROUTER_INSTALL_${_dirvar} is empty.")
    ENDIF()

    # create a empty directory in the install folder
    INSTALL(DIRECTORY DESTINATION "${_dir}"
      DIRECTORY_PERMISSIONS
      OWNER_WRITE OWNER_READ OWNER_EXECUTE
      GROUP_WRITE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE
      COMPONENT Router
      )
  ENDFOREACH()
ENDIF()
