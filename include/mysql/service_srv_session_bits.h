/*  Copyright (c) 2019, 2025, Oracle and/or its affiliates.

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

#ifndef MYSQL_SRV_SESSION_SERVICE_BITS_INCLUDED
#define MYSQL_SRV_SESSION_SERVICE_BITS_INCLUDED

/**
  @file
  These are the common definitions between the plugin service for sessions
  and the component service extension for sessions.
  Note that this file is part of both the PLUGIN API/ABI and the component
  service API.
*/

#ifdef __cplusplus
class Srv_session;
typedef class Srv_session *MYSQL_SESSION;
#else
struct Srv_session;
typedef struct Srv_session *MYSQL_SESSION;
#endif

typedef void (*srv_session_error_cb)(void *ctx, unsigned int sql_errno,
                                     const char *err_msg);

#endif  // MYSQL_SRV_SESSION_SERVICE_BITS_INCLUDED
