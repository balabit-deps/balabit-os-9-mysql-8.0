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

#include <m_ctype.h>
#include <m_string.h>
#include <my_dir.h>
#include <my_getopt.h>
#include <my_sys.h>
#include <signal.h>
#include <violite.h>

#include "errmsg.h"
#include "mysql.h"

const char *VER = "0.2";

#ifndef NDEBUG
const char *default_dbug_option = "d:t:O,/tmp/viotest-ssl.trace";
#endif

void fatal_error(const char *r) {
  perror(r);
  exit(0);
}

void print_usage() {
  printf("viossl-test: testing SSL virtual IO. Usage:\n");
  printf(
      "viossl-test server-key server-cert client-key client-cert [CAfile] "
      "[CApath]\n");
}

int main(int argc, char **argv) {
  char *server_key = nullptr;
  char *server_cert = nullptr;
  char *client_key = nullptr;
  char *client_cert = nullptr;
  char *ca_file = nullptr;
  char *ca_path = nullptr;
  int child_pid, sv[2];
  struct st_VioSSLAcceptorFd *ssl_acceptor = nullptr;
  struct st_VioSSLConnectorFd *ssl_connector = nullptr;
  Vio *client_vio = nullptr;
  Vio *server_vio = nullptr;
  enum enum_ssl_init_error ssl_init_error;
  unsigned long ssl_error;

  MY_INIT(argv[0]);
  DBUG_PROCESS(argv[0]);
  DBUG_PUSH(default_dbug_option);

  if (argc < 5) {
    print_usage();
    return 1;
  }

  server_key = argv[1];
  server_cert = argv[2];
  client_key = argv[3];
  client_cert = argv[4];
  if (argc > 5) ca_file = argv[5];
  if (argc > 6) ca_path = argv[6];
  printf("Server key/cert : %s/%s\n", server_key, server_cert);
  printf("Client key/cert : %s/%s\n", client_key, client_cert);
  if (ca_file != nullptr) printf("CAfile          : %s\n", ca_file);
  if (ca_path != nullptr) printf("CApath          : %s\n", ca_path);

  if (socketpair(PF_UNIX, SOCK_STREAM, IPPROTO_IP, sv) == -1)
    fatal_error("socketpair");

  ssl_acceptor =
      new_VioSSLAcceptorFd(server_key, server_cert, ca_file, ca_path);
  ssl_connector = new_VioSSLConnectorFd(client_key, client_cert, ca_file,
                                        ca_path, &ssl_init_error);

  client_vio = (Vio *)my_malloc(sizeof(Vio), MYF(0));
  client_vio->sd = sv[0];
  sslconnect(ssl_connector, client_vio, &ssl_error);
  server_vio = (Vio *)my_malloc(sizeof(Vio), MYF(0));
  server_vio->sd = sv[1];
  sslaccept(ssl_acceptor, server_vio, &ssl_error);

  printf("Socketpair: %d , %d\n", client_vio->sd, server_vio->sd);

  child_pid = fork();
  if (child_pid == -1) {
    my_free(ssl_acceptor);
    my_free(ssl_connector);
    fatal_error("fork");
  }
  if (child_pid == 0) {
    /* child, therefore, client */
    char xbuf[100];
    int r = vio_ssl_read(client_vio, xbuf, sizeof(xbuf));
    if (r <= 0) {
      my_free(ssl_acceptor);
      my_free(ssl_connector);
      fatal_error("client:SSL_read");
    }
    xbuf[r] = 0;
    printf("client:got %s\n", xbuf);
    my_free(client_vio);
    my_free(ssl_acceptor);
    my_free(ssl_connector);
    sleep(1);
  } else {
    const char *s = "Huhuhuh";
    int r = vio_ssl_write(server_vio, (uchar *)s, strlen(s));
    if (r <= 0) {
      my_free(ssl_acceptor);
      my_free(ssl_connector);
      fatal_error("server:SSL_write");
    }
    my_free(server_vio);
    my_free(ssl_acceptor);
    my_free(ssl_connector);
    sleep(1);
  }
  return 0;
}
