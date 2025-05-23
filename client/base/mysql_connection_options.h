/*
   Copyright (c) 2014, 2025, Oracle and/or its affiliates.

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

#ifndef MYSQL_CONNECTION_OPTIONS_INCLUDED
#define MYSQL_CONNECTION_OPTIONS_INCLUDED

#include <optional>
#include <vector>

#include "client/base/abstract_program.h"
#include "client/base/composite_options_provider.h"
#include "client/base/i_connection_factory.h"
#include "client/client_priv.h"
#include "my_compiler.h"
#include "my_inttypes.h"

namespace Mysql {
namespace Tools {
namespace Base {
namespace Options {

/**
  Options provider providing options to specify connection to MySQL server.
 */
class Mysql_connection_options : public Composite_options_provider,
                                 I_connection_factory {
 private:
  /**
    Options provider enclosing options related to SSL settings of connection
    to MySQL server.
   */
  class Ssl_options : public Abstract_options_provider {
   public:
    /**
      Creates all options that will be provided.
      Implementation of Abstract_options_provider virtual method.
     */
    void create_options() override;

    /**
      Applies option values to MYSQL connection structure.
     */
    bool apply_for_connection(MYSQL *connection);

    /**
      Checks the connection for SSL validity
    */
    bool check_connection(MYSQL *connection);

   private:
    std::optional<std::string> m_ssl_mode_string;
    std::optional<std::string> m_ssl_fips_mode_string;

    void ca_option_callback(char *argument);
    void mode_option_callback(char *argument);
    void fips_mode_option_callback(char *argument);
  };

 public:
  /**
    Constructs new MySQL server connection options provider. Calling this
    function from multiple threads simultaneously is not thread safe.
    @param program Pointer to main program class.
   */
  explicit Mysql_connection_options(Abstract_program *program);

  /**
    Creates all options that will be provided.
    Implementation of Abstract_options_provider virtual method.
   */
  void create_options() override;

  /**
    Provides new connection to MySQL database server based on option values.
    Implementation of I_connection_factory interface.
   */
  MYSQL *create_connection() override;

  /**
    Retrieves charset that will be used in new MySQL connections.. Can be NULL
    if none was set explicitly.
   */
  CHARSET_INFO *get_current_charset() const;

  /**
    Sets charset that will be used in new MySQL connections.
   */
  void set_current_charset(CHARSET_INFO *charset);

 private:
  /**
    Returns pointer to constant array containing specified string or NULL
    value if string has length 0.
   */
  const char *get_null_or_string(std::optional<std::string> &maybeString);

  /**
    Prints database connection error and exits program.
   */
  void db_error(MYSQL *connection, const char *when);
#ifdef _WIN32
  void pipe_protocol_callback(char *not_used [[maybe_unused]]);
#endif
  void protocol_callback(char *not_used [[maybe_unused]]);

  static bool mysql_inited;

  Ssl_options m_ssl_options_provider;
  Abstract_program *m_program;
  std::optional<std::string> m_protocol_string;
  uint32 m_protocol;
  std::optional<std::string> m_bind_addr;
  std::optional<std::string> m_host;
  uint32 m_mysql_port;
  std::optional<std::string> m_mysql_unix_port;
#if defined(_WIN32)
  std::optional<std::string> m_shared_memory_base_name;
#endif
  std::optional<std::string> m_default_auth;
  std::optional<std::string> m_plugin_dir;
  uint32 m_net_buffer_length;
  uint32 m_max_allowed_packet;
  bool m_compress;
  std::optional<std::string> m_user;
  std::optional<std::string> m_password[3];
  std::optional<std::string> m_default_charset;
  std::optional<std::string> m_server_public_key;
  bool m_get_server_public_key;
  uint m_zstd_compress_level;
  std::optional<std::string> m_compress_algorithm;
};

}  // namespace Options
}  // namespace Base
}  // namespace Tools
}  // namespace Mysql

#endif
