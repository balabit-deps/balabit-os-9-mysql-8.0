/*
  Copyright (c) 2022, 2025, Oracle and/or its affiliates.

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
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "classic_connect.h"

#include <chrono>
#include <memory>
#include <system_error>

#include "basic_protocol_splicer.h"
#include "classic_connection_base.h"
#include "classic_frame.h"
#include "destination_error.h"
#include "mysql/harness/logging/logging.h"
#include "mysql/harness/net_ts/impl/poll.h"
#include "mysql/harness/net_ts/internet.h"
#include "mysql/harness/stdx/expected.h"
#include "mysql/harness/utility/string.h"  // join
#include "mysqlrouter/connection_pool_component.h"
#include "mysqlrouter/routing_component.h"
#include "mysqlrouter/utils.h"  // to_string
#include "processor.h"

IMPORT_LOG_FUNCTIONS()

// create a destination id that's understood by make_tcp_address()
static std::string destination_id_from_endpoint(
    const std::string &host_name, const std::string &service_name) {
  if (net::ip::make_address_v6(host_name.c_str())) {
    return "[" + host_name + "]:" + service_name;
  } else {
    return host_name + ":" + service_name;
  }
}

static std::string destination_id_from_endpoint(
    const net::ip::tcp::resolver::results_type::iterator::value_type
        &endpoint) {
  return destination_id_from_endpoint(endpoint.host_name(),
                                      endpoint.service_name());
}

stdx::expected<Processor::Result, std::error_code> ConnectProcessor::process() {
  switch (stage()) {
    case Stage::InitDestination:
      return init_destination();
    case Stage::Resolve:
      return resolve();
    case Stage::InitEndpoint:
      return init_endpoint();
    case Stage::FromPool:
      return from_pool();
    case Stage::NextEndpoint:
      return next_endpoint();
    case Stage::NextDestination:
      return next_destination();
    case Stage::InitConnect:
      return init_connect();
    case Stage::Connect:
      return connect();
    case Stage::ConnectFinish:
      return connect_finish();
    case Stage::Connected:
      return connected();
    case Stage::Error:
      return error();
    case Stage::Done:
      return Result::Done;
  }

  harness_assert_this_should_not_execute();
}

static TlsSwitchableConnection make_connection_from_pooled(
    PooledClassicConnection &&other) {
  return {std::move(other.connection()),
          nullptr,  // routing_conn
          other.ssl_mode(), std::make_unique<Channel>(std::move(other.ssl())),
          std::make_unique<ClassicProtocolState>(
              other.server_capabilities(), other.client_capabilities(),
              other.server_greeting(), other.username(), other.schema(),
              other.attributes())};
}

// get the socket-error from a connection.
//
// error   if getting socket error failed.
// success if error could be fetched
static stdx::expected<std::error_code, std::error_code> sock_error_code(
    TlsSwitchableConnection &conn) {
  auto tcp_conn = dynamic_cast<TcpConnection *>(conn.connection().get());

  net::socket_base::error sock_err;
  const auto getopt_res = tcp_conn->get_option(sock_err);
  if (!getopt_res) return stdx::make_unexpected(getopt_res.error());

  if (sock_err.value() != 0) {
    return std::error_code {
      sock_err.value(),
#if defined(_WIN32)
          std::system_category()
#else
          std::generic_category()
#endif
    };
  }

  return {};
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::init_destination() {
  std::vector<std::string> dests;
  for (const auto &dest : destinations_) {
    dests.push_back(destination_id_from_endpoint(dest->hostname(),
                                                 std::to_string(dest->port())));
  }

  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::init_destination: " +
                                   mysql_harness::join(dests, ",")));
  }

  // reset the error-code for this destination.
  destination_ec_.clear();

  all_quarantined_ = true;

  destinations_it_ = destinations_.begin();
  if (destinations_it_ == destinations_.end()) {
    if (connect_errors_.empty()) {
      // no backends
      log_debug("init_destination(): the destinations list is empty");

      connect_errors_.emplace_back(
          "no destinations",
          make_error_code(DestinationsErrc::kNoDestinations));
    }

    stage(Stage::Error);
    return Result::Again;
  }

  const auto &destination = *destinations_it_;

  if (is_destination_good(destination->hostname(), destination->port())) {
    stage(Stage::Resolve);
  } else {
    connect_errors_.emplace_back(
        "connect(/* " + destination->hostname() + ":" +
            std::to_string(destination->port()) + " */)",
        make_error_code(DestinationsErrc::kQuarantined));

    stage(Stage::NextDestination);
  }

  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code> ConnectProcessor::resolve() {
  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::resolve"));
  }

  const auto &destination = *destinations_it_;

  if (!destination->good()) {
    stage(Stage::NextDestination);

    return Result::Again;
  }

  if (!connection()->get_destination_id().empty()) {
    // already connected before. Make sure the same endpoint is connected.
    const auto dest_id = connection()->get_destination_id();

    if (auto &tr = tracer()) {
      tr.trace(Tracer::Event().stage("connect::sticky: " + dest_id));
    }

    if (dest_id !=
        destination_id_from_endpoint(destination->hostname(),
                                     std::to_string(destination->port()))) {
      stage(Stage::NextDestination);
      return Result::Again;
    }
  }

  auto started = std::chrono::steady_clock::now();

  const auto resolve_res = resolver_.resolve(
      destination->hostname(), std::to_string(destination->port()));

  if (!resolve_res) {
    auto ec = resolve_res.error();

    const auto resolve_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
    connect_errors_.emplace_back(
        "resolve(" + destination->hostname() + ") failed after " +
            std::to_string(resolve_duration.count()) + "ms",
        ec);

    log_debug("resolve(%s,%d) failed: %s:%s",  //
              destination->hostname().c_str(), destination->port(),
              ec.category().name(), ec.message().c_str());

    destination_ec_ = ec;

    // resolve(...) failed, move host:port to the quarantine to monitor the
    // solve to come back.

    auto hostname = destination->hostname();
    auto port = destination->port();

    auto &ctx = connection()->context();

    if (ctx.shared_quarantine().update({hostname, port}, false)) {
      log_debug("[%s] add destination '%s:%d' to quarantine",
                ctx.get_name().c_str(), hostname.c_str(), port);
    } else {
      // failed to connect, but not quarantined. Don't close the ports, yet.
      all_quarantined_ = false;
    }

    stage(Stage::NextDestination);
    return Result::Again;
  }

  endpoints_ = *resolve_res;

#if 0
  std::cerr << __LINE__ << ": " << destination->hostname() << "\n";
  for (auto const &ep : endpoints_) {
    std::cerr << __LINE__ << ": .. " << ep.endpoint() << "\n";
  }
#endif

  stage(Stage::InitEndpoint);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::init_endpoint() {
  // trace(Tracer::Event().stage("connect::init_endpoint"));

  endpoints_it_ = endpoints_.begin();

  stage(Stage::InitConnect);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::init_connect() {
  // trace(Tracer::Event().stage("connect::init_connect"));

  (void)connection()->socket_splicer()->server_conn().close();

  connection()->connect_error_code({});  // reset the connect-error-code.

  auto endpoint = *endpoints_it_;

  server_endpoint_ = endpoint.endpoint();

  stage(Stage::FromPool);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::from_pool() {
  auto *socket_splicer = connection()->socket_splicer();
  auto client_protocol = connection()->client_protocol();

  if (!client_protocol->client_greeting()) {
    // taking a connection from the pool requires that the client's greeting
    // must been received already.
    stage(Stage::Connect);
    return Result::Again;
  }

  auto &pools = ConnectionPoolComponent::get_instance();

  if (auto pool = pools.get(ConnectionPoolComponent::default_pool_name())) {
    // pop the first connection from the pool that matches our requirements
    //
    // - endpoint
    // - capabilities

    auto client_caps = client_protocol->shared_capabilities();

    client_caps
        // connection specific.
        .reset(classic_protocol::capabilities::pos::ssl)
        .reset(classic_protocol::capabilities::pos::compress)
        .reset(classic_protocol::capabilities::pos::compress_zstd)
        // session specific capabilities which can be recovered by
        // set_server_option()
        .reset(classic_protocol::capabilities::pos::multi_statements);

    auto pool_res = pool->pop_if(
        [client_caps, ep = mysqlrouter::to_string(server_endpoint_),
         requires_tls = connection()->requires_tls()](const auto &pooled_conn) {
          auto pooled_caps = pooled_conn.shared_capabilities();

          pooled_caps.reset(classic_protocol::capabilities::pos::ssl)
              .reset(classic_protocol::capabilities::pos::compress)
              .reset(classic_protocol::capabilities::pos::compress_zstd)
              .reset(classic_protocol::capabilities::pos::multi_statements);

          return (pooled_conn.endpoint() == ep &&  //
                  client_caps == pooled_caps &&    //
                  (requires_tls == (bool)pooled_conn.ssl()));
        });

    if (pool_res) {
      // check if the socket is closed.
      std::array<net::impl::poll::poll_fd, 1> fds{
          {{pool_res->connection()->native_handle(), POLLIN, 0}}};
      auto poll_res = net::impl::poll::poll(fds.data(), fds.size(),
                                            std::chrono::milliseconds(0));
      if (!poll_res && poll_res.error() == std::errc::timed_out) {
        // nothing to read -> socket is still up.
        if (auto &tr = tracer()) {
          tr.trace(Tracer::Event().stage(
              "connect::from_pool: " +
              destination_id_from_endpoint(*endpoints_it_)));
        }

        // if the socket would be closed, recv() would return 0 for "eof".
        //
        // socket is still alive. good.
        socket_splicer->server_conn() =
            make_connection_from_pooled(std::move(*pool_res));

        (void)socket_splicer->server_conn().connection()->set_io_context(
            socket_splicer->client_conn().connection()->io_ctx());

        connection()->server_address(socket_splicer->server_conn().endpoint());

        stage(Stage::Connected);
        return Result::Again;
      }

      // socket is dead. try the next one.
      return Result::Again;
    }
  }

  stage(Stage::Connect);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code> ConnectProcessor::connect() {
  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::connect: " +
                                   mysqlrouter::to_string(server_endpoint_)));
  }
#if 0
  if (log_level_is_handled(mysql_harness::logging::LogLevel::kDebug)) {
    log_debug("trying %s", mysqlrouter::to_string(server_endpoint_).c_str());
  }
#endif

  const int socket_flags {
#if defined(SOCK_NONBLOCK)
    // linux|freebsd|sol11.4 allows to set NONBLOCK as part of the socket()
    // call to save the extra syscall
    SOCK_NONBLOCK
#endif
  };

  net::ip::tcp::socket server_sock(io_ctx_);

  auto open_res = server_sock.open(server_endpoint_.protocol(), socket_flags);
  if (!open_res) return open_res.get_unexpected();

  const auto non_block_res = server_sock.native_non_blocking(true);
  if (!non_block_res) return non_block_res.get_unexpected();

  server_sock.set_option(net::ip::tcp::no_delay{true});

#ifdef FUTURE_TASK_USE_SOURCE_ADDRESS
  /* set the source address to take a specific route.
   *
   *
   */

  // IP address of the interface we want to route-through.
  std::string src_addr_str;

  // src_addr_str = "192.168.178.78";

  if (!src_addr_str.empty()) {
    const auto src_addr_res = net::ip::make_address_v4(src_addr_str.c_str());
    if (!src_addr_res) return src_addr_res.get_unexpected();

#if defined(IP_BIND_ADDRESS_NO_PORT)
    // linux 4.2 introduced IP_BIND_ADDRESS_NO_PORT to delay assigning a
    // source-port until connect()
    net::socket_option::integer<IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT> sockopt;

    const auto setsockopt_res = server_sock.set_option(sockopt);
    if (!setsockopt_res) {
      // if the glibc supports IP_BIND_ADDRESS_NO_PORT, but the kernel
      // doesn't: ignore it.
      if (setsockopt_res.error() !=
          make_error_code(std::errc::invalid_argument)) {
        log_warning(
            "%d: setsockopt(IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT) "
            "failed: "
            "%s",
            __LINE__, setsockopt_res.error().message().c_str());
        return setsockopt_res.get_unexpected();
      }
    }
#endif

    const auto bind_res = server_sock.bind(net::ip::tcp::endpoint(
        src_addr_res.value_or(net::ip::address_v4{}), 0));
    if (!bind_res) return bind_res.get_unexpected();
  }
#endif

  connect_started_ = std::chrono::steady_clock::now();

  const auto connect_res = server_sock.connect(server_endpoint_);

  // don't assign the connection if disconnect is requested.
  //
  // assigning the connection would lead to a deadlock in start_acceptor()
  auto disconnected_requested =
      connection()->disconnect_request([this, &server_sock](bool req) {
        if (req) return true;

        connection()->socket_splicer()->server_conn().assign_connection(
            std::make_unique<TcpConnection>(std::move(server_sock),
                                            server_endpoint_));

        return false;
      });
  if (disconnected_requested) {
    connection()->connect_error_code(
        make_error_code(std::errc::operation_canceled));

    stage(Stage::Done);
    return Result::Again;
  }

  if (!connect_res) {
    const auto ec = connect_res.error();
    if (ec == make_error_condition(std::errc::operation_in_progress) ||
        ec == make_error_condition(std::errc::operation_would_block)) {
      // connect in progress, wait for completion.
      stage(Stage::ConnectFinish);

      if (auto &tr = tracer()) {
        tr.trace(Tracer::Event().stage("connect::wait"));
      }

      auto &timer = connection()->connect_timer();

      timer.expires_after(
          connection()->context().get_destination_connect_timeout());

      timer.async_wait([this](std::error_code ec) {
        if (ec) return;

        if (auto &tr = tracer()) {
          tr.trace(Tracer::Event().stage("connect::timed_out"));
        }

        auto *socket_splicer = connection()->socket_splicer();
        auto &server_conn = socket_splicer->server_conn();

        connection()->connect_error_code(make_error_code(std::errc::timed_out));

        (void)server_conn.cancel();
      });

      connection()->socket_splicer()->server_conn().async_wait_error(
          [conn = connection()](std::error_code ec) {
            if (ec) return;

            auto *socket_splicer = conn->socket_splicer();
            auto &server_conn = socket_splicer->server_conn();

            auto sock_ec_res = sock_error_code(server_conn);
            if (!sock_ec_res) {
              conn->connect_error_code(sock_ec_res.error());
            } else {
              conn->connect_error_code(sock_ec_res.value());
            }

            // cancel all the other waiters
            (void)server_conn.cancel();
          });

      return Result::SendableToServer;
    } else {
      log_debug("connect(%s, %d) failed: %s:%s",
                server_endpoint_.address().to_string().c_str(),
                server_endpoint_.port(), connect_res.error().category().name(),
                connect_res.error().message().c_str());
      connection()->connect_error_code(ec);

      stage(Stage::ConnectFinish);
      return Result::Again;
    }
  }

  stage(Stage::Connected);
  return Result::Again;
}

namespace {
std::string pretty_endpoint(const net::ip::tcp::endpoint &ep,
                            const std::string &hostname) {
  if (ep.address().to_string() == hostname) return mysqlrouter::to_string(ep);

  return mysqlrouter::to_string(ep) + " /* " + hostname + " */";
}
}  // namespace

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::connect_finish() {
  auto connect_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - connect_started_);

  connection()->connect_timer().cancel();

  auto &server_conn = connection()->socket_splicer()->server_conn();

  // cancel all handlers.
  (void)server_conn.cancel();

  if (auto ec = connection()->connect_error_code()) {
    log_debug("connect(%s, %d) failed: %s:%s",
              server_endpoint_.address().to_string().c_str(),
              server_endpoint_.port(), ec.category().name(),
              ec.message().c_str());

    if (auto &tr = tracer()) {
      tr.trace(
          Tracer::Event().stage("connect::connect_finish: " + ec.message()));
    }

    connect_errors_.emplace_back(
        "connect(" +
            pretty_endpoint(server_endpoint_, (*destinations_it_)->hostname()) +
            ") failed after " + std::to_string(connect_duration.count()) + "ms",
        ec);

    destination_ec_ = ec;

    stage(Stage::NextEndpoint);
    return Result::Again;
  }

  auto sock_ec_res = sock_error_code(server_conn);
  if (!sock_ec_res) {
    auto ec = sock_ec_res.error();

    log_debug("connect(%s, %d) failed: %s:%s",
              server_endpoint_.address().to_string().c_str(),
              server_endpoint_.port(), ec.category().name(),
              ec.message().c_str());

    if (auto &tr = tracer()) {
      tr.trace(
          Tracer::Event().stage("connect::connect_finish: " + ec.message()));
    }

    connect_errors_.emplace_back(
        "connect(" +
            pretty_endpoint(server_endpoint_, (*destinations_it_)->hostname()) +
            ")::getsockopt()",
        ec);

    destination_ec_ = ec;

    stage(Stage::NextEndpoint);
    return Result::Again;
  }

  auto sock_ec = *sock_ec_res;

  if (sock_ec != std::error_code{}) {
    log_debug("connect(%s, %d) failed: %s:%s",
              server_endpoint_.address().to_string().c_str(),
              server_endpoint_.port(), sock_ec.category().name(),
              sock_ec.message().c_str());

    if (auto &tr = tracer()) {
      tr.trace(Tracer::Event().stage("connect::connect_finish: " +
                                     sock_ec.message()));
    }

    connect_errors_.emplace_back(
        "connect(" +
            pretty_endpoint(server_endpoint_, (*destinations_it_)->hostname()) +
            ") failed after " + std::to_string(connect_duration.count()) + "ms",
        sock_ec);

    destination_ec_ = sock_ec;

    stage(Stage::NextEndpoint);
    return Result::Again;
  }

  stage(Stage::Connected);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::next_endpoint() {
  (void)connection()->socket_splicer()->server_conn().close();

  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::next_endpoint"));
  }

  std::advance(endpoints_it_, 1);

  if (endpoints_it_ != endpoints_.end()) {
    stage(Stage::InitConnect);
    return Result::Again;
  }

  // no more endpoints for this destination.

  auto &destination = *destinations_it_;

  // report back the connect status to the destination
  destination->connect_status(destination_ec_);

  if (destination_ec_) {
    auto hostname = destination->hostname();
    auto port = destination->port();

    auto &ctx = connection()->context();

    if (ctx.shared_quarantine().update({hostname, port}, false)) {
      log_debug("[%s] add destination '%s:%d' to quarantine",
                ctx.get_name().c_str(), hostname.c_str(), port);
    } else {
      // failed to connect, but not quarantined. Don't close the ports, yet.
      all_quarantined_ = false;
    }
  }

  stage(Stage::NextDestination);
  return Result::Again;
}

bool ConnectProcessor::is_destination_good(const std::string &hostname,
                                           uint16_t port) const {
  const auto &ctx = connection()->context();

  const auto is_quarantined =
      ctx.shared_quarantine().is_quarantined({hostname, port});
  if (is_quarantined) {
    log_debug("[%s] skip quarantined destination '%s:%d'",
              ctx.get_name().c_str(), hostname.c_str(), port);

    return false;
  }

  return true;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::next_destination() {
  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::next_destination"));
  }
  do {
    std::advance(destinations_it_, 1);

    if (destinations_it_ == std::end(destinations_)) break;

    const auto &destination = *destinations_it_;

    if (is_destination_good(destination->hostname(), destination->port())) {
      break;
    }

    connect_errors_.emplace_back(
        "connect(/* " + destination->hostname() + ":" +
            std::to_string(destination->port()) + " */)",
        make_error_code(DestinationsErrc::kQuarantined));
  } while (true);

  if (destinations_it_ != destinations_.end()) {
    // next destination
    stage(Stage::Resolve);
    return Result::Again;
  }

  // no more destinations.

  if (auto refresh_res =
          connection()->destinations()->refresh_destinations(destinations_)) {
    destinations_ = std::move(refresh_res.value());

    stage(Stage::InitDestination);
    return Result::Again;
  }

  connect_errors_.emplace_back(
      "end of destinations",
      make_error_code(DestinationsErrc::kNoDestinations));

  // we couldn't connect to any of the destinations. Give up.
  stage(Stage::Error);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code>
ConnectProcessor::connected() {
  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::connected"));
  }

  // remember the destination we connected too for connection-sharing.
  connection()->destination_id(destination_id_from_endpoint(*endpoints_it_));

  connection()->server_address(
      connection()->socket_splicer()->server_conn().endpoint());

  {
    const auto &dest = (*destinations_it_);

    connection()->context().shared_quarantine().update(
        {dest->hostname(), dest->port()}, true);
  }

  // back to the caller.
  stage(Stage::Done);
  return Result::Again;
}

stdx::expected<Processor::Result, std::error_code> ConnectProcessor::error() {
  // close the socket if it is still open.
  (void)connection()->socket_splicer()->server_conn().close();

  if (auto &tr = tracer()) {
    tr.trace(Tracer::Event().stage("connect::error"));
  }

  const auto last_ec = connect_errors_.back().second;

  connection()->connect_error_code(last_ec);

  {
    std::string msg;
    for (auto [err, ec] : connect_errors_) {
      if (!msg.empty()) {
        msg += ", ";
      }
      msg += err;
      msg += ": ";
      msg += ec.message();
    }

    log_error("[%s] connecting to backend(s) for client from %s failed: %s",
              connection()->context().get_name().c_str(),
              connection()->socket_splicer()->client_conn().endpoint().c_str(),
              msg.c_str());
  }

  if (last_ec == make_error_condition(std::errc::too_many_files_open) ||
      last_ec ==
          make_error_condition(std::errc::too_many_files_open_in_system)) {
    // release file-descriptors on the connection pool when out-of-fds is
    // noticed.
    //
    // don't retry as router may run into an infinite loop.
    ConnectionPoolComponent::get_instance().clear();
  } else if (connection()->get_destination_id().empty() && all_quarantined_) {
    // fresh-connect == "destiantion-id is empty"

    // if there are no destinations for a fresh connect, close the
    // acceptor-ports
    if (auto &tr = tracer()) {
      tr.trace(Tracer::Event().stage("connect::error::all_down"));
    }
    // all backends are down.
    MySQLRoutingComponent::get_instance()
        .api(connection()->context().get_id())
        .stop_socket_acceptors();
  }

  connection()->server_protocol()->handshake_state(
      ClassicProtocolState::HandshakeState::kConnected);
  connection()->authenticated(false);

  stage(Stage::Done);

  on_error_({2003, "Can't connect to remote MySQL server", "HY000"});

  return Result::Again;
}
