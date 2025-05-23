/* Copyright (c) 2000, 2025, Oracle and/or its affiliates.

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
#ifndef AUTH_ACLS_INCLUDED
#define AUTH_ACLS_INCLUDED

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

/* Total Number of ACLs present in mysql.user */
#define NUM_ACLS 31

typedef uint32_t Access_bitmask;

#define SELECT_ACL ((Access_bitmask)1 << 0)
#define INSERT_ACL ((Access_bitmask)1 << 1)
#define UPDATE_ACL ((Access_bitmask)1 << 2)
#define DELETE_ACL ((Access_bitmask)1 << 3)
#define CREATE_ACL ((Access_bitmask)1 << 4)
#define DROP_ACL ((Access_bitmask)1 << 5)
#define RELOAD_ACL ((Access_bitmask)1 << 6)
#define SHUTDOWN_ACL ((Access_bitmask)1 << 7)
#define PROCESS_ACL ((Access_bitmask)1 << 8)
#define FILE_ACL ((Access_bitmask)1 << 9)
/** Set to true by both
  GRANT GRANT OPTION ... TO ...
and
  GRANT ... TO ... WITH GRANT OPTION

  Stored into the relevant column in the priv tables for static privileges.
  And into the the GRANT_OPTION column for dynamic privilege grants.
  Note that, once granted GRANT_OPTION applies to all static privs on the
  same level, i.e. the following:
  GRANT SELECT ON *.* TO foo;
  GRANT INSERT ON *.* TO foo WITH GRANT OPTION;
  is equivalent to:
  GRANT SELECT,INSERT ON *.* TO foo WITH GRANT OPTION;
  And is also equivalent to
  GRANT SELECT,INSERT, GRANT OPTION ON *.* TO foo;

  @sa @ref LEX::grant_privilege
*/
#define GRANT_ACL ((Access_bitmask)1 << 10)
#define REFERENCES_ACL ((Access_bitmask)1 << 11)
#define INDEX_ACL ((Access_bitmask)1 << 12)
#define ALTER_ACL ((Access_bitmask)1 << 13)
#define SHOW_DB_ACL ((Access_bitmask)1 << 14)
#define SUPER_ACL ((Access_bitmask)1 << 15)
#define CREATE_TMP_ACL ((Access_bitmask)1 << 16)
#define LOCK_TABLES_ACL ((Access_bitmask)1 << 17)
#define EXECUTE_ACL ((Access_bitmask)1 << 18)
#define REPL_SLAVE_ACL ((Access_bitmask)1 << 19)
#define REPL_CLIENT_ACL ((Access_bitmask)1 << 20)
#define CREATE_VIEW_ACL ((Access_bitmask)1 << 21)
#define SHOW_VIEW_ACL ((Access_bitmask)1 << 22)
#define CREATE_PROC_ACL ((Access_bitmask)1 << 23)
#define ALTER_PROC_ACL ((Access_bitmask)1 << 24)
#define CREATE_USER_ACL ((Access_bitmask)1 << 25)
#define EVENT_ACL ((Access_bitmask)1 << 26)
#define TRIGGER_ACL ((Access_bitmask)1 << 27)
#define CREATE_TABLESPACE_ACL ((Access_bitmask)1 << 28)
#define CREATE_ROLE_ACL ((Access_bitmask)1 << 29)
#define DROP_ROLE_ACL ((Access_bitmask)1 << 30)
/*
  don't forget to update
  1. static struct show_privileges_st sys_privileges[]
  2. static const char *command_array[] and static uint command_lengths[]
  3. mysql_system_tables.sql and mysql_system_tables_fix.sql
  4. acl_init() or whatever - to define behaviour for old privilege tables
  5. sql_yacc.yy - for GRANT/REVOKE to work
  6. global_privileges map and vector
*/

#define NO_ACCESS ((Access_bitmask)1 << NUM_ACLS)
#define ALL_ACCESS (NO_ACCESS - 1)

/**
  Privileges to perform database related operations.
  Use this macro over DB_ACLS unless there is real need to use
  additional privileges present in the DB_ACLS
*/
#define DB_OP_ACLS                                                             \
  (UPDATE_ACL | SELECT_ACL | INSERT_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL | \
   REFERENCES_ACL | INDEX_ACL | ALTER_ACL | CREATE_TMP_ACL | LOCK_TABLES_ACL | \
   EXECUTE_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL | CREATE_PROC_ACL |           \
   ALTER_PROC_ACL | EVENT_ACL | TRIGGER_ACL)

/**
  Privileges to perform table related operations.
  Use this macro over TABLE_ACLS unless there is real need to use
  additional privileges present in the DB_ACLS
*/
#define TABLE_OP_ACLS                                                          \
  (SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL | \
   REFERENCES_ACL | INDEX_ACL | ALTER_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL |  \
   TRIGGER_ACL)

/**
  Privileges to modify or execute stored procedures.
  Use this macro over PROC_ACLS unless there is real need to use
  additional privileges present in the PROC_ACLS
*/
#define PROC_OP_ACLS (ALTER_PROC_ACL | EXECUTE_ACL)

/**
  Represents all privileges which could be granted to users at DB-level. It
  essentially represents all the privileges present in the mysql.db table.
*/
#define DB_ACLS (DB_OP_ACLS | GRANT_ACL)

/**
  Represents all privileges which could be granted to users at table-level. It
  essentially represents all the privileges present in the mysql.tables_priv
  table.
*/
#define TABLE_ACLS (TABLE_OP_ACLS | GRANT_ACL)

/**
  Represents all privileges which could be granted to users at column-level. It
  essentially represents all the privileges present in the columns_priv table.
*/
#define COL_ACLS (SELECT_ACL | INSERT_ACL | UPDATE_ACL | REFERENCES_ACL)

/**
  Represents all privileges which could be granted to users for stored
  procedures. It essentially represents all the privileges present in the
  mysql.procs_priv table.
*/
#define PROC_ACLS (PROC_OP_ACLS | GRANT_ACL)

/**
  Represents all privileges which are required to show the stored procedure.
*/
#define SHOW_PROC_ACLS (PROC_OP_ACLS | CREATE_PROC_ACL)

/**
  Represents all privileges which could be granted to users globally.
  It essentially represents all the privileges present in the mysql.user table
*/
#define GLOBAL_ACLS                                                            \
  (SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL | \
   RELOAD_ACL | SHUTDOWN_ACL | PROCESS_ACL | FILE_ACL | GRANT_ACL |            \
   REFERENCES_ACL | INDEX_ACL | ALTER_ACL | SHOW_DB_ACL | SUPER_ACL |          \
   CREATE_TMP_ACL | LOCK_TABLES_ACL | REPL_SLAVE_ACL | REPL_CLIENT_ACL |       \
   EXECUTE_ACL | CREATE_VIEW_ACL | SHOW_VIEW_ACL | CREATE_PROC_ACL |           \
   ALTER_PROC_ACL | CREATE_USER_ACL | EVENT_ACL | TRIGGER_ACL |                \
   CREATE_TABLESPACE_ACL | CREATE_ROLE_ACL | DROP_ROLE_ACL)

#define DEFAULT_CREATE_PROC_ACLS (ALTER_PROC_ACL | EXECUTE_ACL)

/**
  Table-level privileges which are automatically "granted" to everyone on
  existing temporary tables (CREATE_ACL is necessary for ALTER ... RENAME).
*/
#define TMP_TABLE_ACLS                                                         \
  (SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL | \
   INDEX_ACL | ALTER_ACL)

/*
  Defines to change the above bits to how things are stored in tables
  This is needed as the 'host' and 'db' table is missing a few privileges
*/

/* Privileges that need to be reallocated (in continuous chunks) */
#define DB_CHUNK0 \
  (SELECT_ACL | INSERT_ACL | UPDATE_ACL | DELETE_ACL | CREATE_ACL | DROP_ACL)
#define DB_CHUNK1 (GRANT_ACL | REFERENCES_ACL | INDEX_ACL | ALTER_ACL)
#define DB_CHUNK2 (CREATE_TMP_ACL | LOCK_TABLES_ACL)
#define DB_CHUNK3 \
  (CREATE_VIEW_ACL | SHOW_VIEW_ACL | CREATE_PROC_ACL | ALTER_PROC_ACL)
#define DB_CHUNK4 (EXECUTE_ACL)
#define DB_CHUNK5 (EVENT_ACL | TRIGGER_ACL)

#define fix_rights_for_db(A)                                               \
  (((A)&DB_CHUNK0) | (((A) << 4) & DB_CHUNK1) | (((A) << 6) & DB_CHUNK2) | \
   (((A) << 9) & DB_CHUNK3) | (((A) << 2) & DB_CHUNK4)) |                  \
      (((A) << 9) & DB_CHUNK5)
#define get_rights_for_db(A)                                           \
  (((A)&DB_CHUNK0) | (((A)&DB_CHUNK1) >> 4) | (((A)&DB_CHUNK2) >> 6) | \
   (((A)&DB_CHUNK3) >> 9) | (((A)&DB_CHUNK4) >> 2)) |                  \
      (((A)&DB_CHUNK5) >> 9)
#define TBL_CHUNK0 DB_CHUNK0
#define TBL_CHUNK1 DB_CHUNK1
#define TBL_CHUNK2 (CREATE_VIEW_ACL | SHOW_VIEW_ACL)
#define TBL_CHUNK3 TRIGGER_ACL
#define fix_rights_for_table(A)                                                \
  (((A)&TBL_CHUNK0) | (((A) << 4) & TBL_CHUNK1) | (((A) << 11) & TBL_CHUNK2) | \
   (((A) << 15) & TBL_CHUNK3))
#define get_rights_for_table(A)                                            \
  (((A)&TBL_CHUNK0) | (((A)&TBL_CHUNK1) >> 4) | (((A)&TBL_CHUNK2) >> 11) | \
   (((A)&TBL_CHUNK3) >> 15))
#define fix_rights_for_column(A) (((A)&7) | (((A) & ~7) << 8))
#define get_rights_for_column(A) (((A)&7) | ((A) >> 8))
#define fix_rights_for_procedure(A)                               \
  ((((A) << 18) & EXECUTE_ACL) | (((A) << 23) & ALTER_PROC_ACL) | \
   (((A) << 8) & GRANT_ACL))
#define get_rights_for_procedure(A)                           \
  ((((A)&EXECUTE_ACL) >> 18) | (((A)&ALTER_PROC_ACL) >> 23) | \
   (((A)&GRANT_ACL) >> 8))

extern const std::vector<std::string> global_acls_vector;
extern const std::unordered_map<std::string, int> global_acls_map;

#endif /* AUTH_ACLS_INCLUDED */
