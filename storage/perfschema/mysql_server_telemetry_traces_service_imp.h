/* Copyright (c) 2022, 2025, Oracle and/or its affiliates.

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

#ifndef MYSQL_SERVER_TELEMETRY_TRACES_SERVICE_IMP_H
#define MYSQL_SERVER_TELEMETRY_TRACES_SERVICE_IMP_H

#include <mysql/components/services/mysql_server_telemetry_traces_service.h>
#include <mysql/plugin.h>

#include "pfs_global.h"

/**
  @file storage/perfschema/mysql_server_telemetry_traces_service_imp.h
  The performance schema implementation of server telemetry traces service.
*/
extern SERVICE_TYPE(mysql_server_telemetry_traces_v1)
    SERVICE_IMPLEMENTATION(performance_schema,
                           mysql_server_telemetry_traces_v1);

void initialize_mysql_server_telemetry_traces_service();
void cleanup_mysql_server_telemetry_traces_service();
void server_telemetry_tracing_lock();
void server_telemetry_tracing_unlock();

bool impl_register_telemetry(telemetry_t *telemetry);
void impl_abort_telemetry(THD *thd);
bool impl_unregister_telemetry(telemetry_t *telemetry);

extern mysql_mutex_t LOCK_pfs_tracing_callback;
#ifdef HAVE_PSI_SERVER_TELEMETRY_TRACES_INTERFACE
extern PFS_cacheline_atomic_ptr<telemetry_t *> g_telemetry;
#endif /* HAVE_PSI_SERVER_TELEMETRY_TRACES_INTERFACE */

#endif /* MYSQL_SERVER_TELEMETRY_TRACES_SERVICE_IMP_H */
