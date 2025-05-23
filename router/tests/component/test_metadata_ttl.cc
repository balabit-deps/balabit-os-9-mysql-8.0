/*
  Copyright (c) 2018, 2025, Oracle and/or its affiliates.

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

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "my_config.h"

#include "config_builder.h"
#include "keyring/keyring_manager.h"
#include "mock_server_rest_client.h"
#include "mock_server_testutils.h"
#include "mysql/harness/stdx/ranges.h"  // enumerate
#include "mysqlrouter/cluster_metadata.h"
#include "mysqlrouter/mysql_session.h"
#include "mysqlrouter/rest_client.h"
#include "rest_api_testutils.h"
#include "router_component_test.h"
#include "router_component_testutils.h"
#include "router_config.h"
#include "router_test_helpers.h"
#include "socket_operations.h"
#include "tcp_port_pool.h"

using mysqlrouter::ClusterType;
using mysqlrouter::MySQLSession;
using ::testing::PrintToString;
using namespace std::chrono_literals;
using namespace std::string_literals;

class MetadataChacheTTLTest : public RouterComponentTest {
 protected:
  std::string get_metadata_cache_section(
      ClusterType cluster_type = ClusterType::GR_V2,
      const std::string &ttl = "0.5", const std::string &cluster_name = "test",
      const std::string &ssl_mode = "") {
    const std::string cluster_type_str =
        (cluster_type == ClusterType::RS_V2) ? "rs" : "gr";

    std::map<std::string, std::string> options{
        {"cluster_type", cluster_type_str},
        {"router_id", "1"},
        {"user", router_metadata_username},
        {"connect_timeout", "1"},
        {"metadata_cluster", cluster_name}};

    if (!ttl.empty()) {
      options["ttl"] = ttl;
    }

    if (!ssl_mode.empty()) {
      options["ssl_mode"] = ssl_mode;
    }

    return mysql_harness::ConfigBuilder::build_section(
        "metadata_cache:bootstrap", options);
  }

  std::string get_metadata_cache_routing_section(
      uint16_t router_port, const std::string &role,
      const std::string &strategy, const std::string &mode = "",
      const std::string &section_name = "default",
      const std::string &protocol = "classic") {
    std::map<std::string, std::string> options{
        {"bind_port", std::to_string(router_port)},
        {"destinations", "metadata-cache://test/default?role=" + role},
        {"protocol", protocol}};

    if (!strategy.empty()) {
      options["routing_strategy"] = strategy;
    }

    if (!mode.empty()) {
      options["mode"] = mode;
    }

    return mysql_harness::ConfigBuilder::build_section(
        "routing:" + section_name, options);
  }

  auto get_array_field_value(const std::string &json_string,
                             const std::string &field_name) {
    std::vector<std::string> result;

    rapidjson::Document json_doc;
    json_doc.Parse(json_string.c_str());
    EXPECT_TRUE(json_doc.HasMember(field_name.c_str()))
        << "json:" << json_string;
    EXPECT_TRUE(json_doc[field_name.c_str()].IsArray()) << json_string;

    auto arr = json_doc[field_name.c_str()].GetArray();
    for (size_t i = 0; i < arr.Size(); ++i) {
      result.push_back(arr[i].GetString());
    }

    return result;
  }

  int get_ttl_queries_count(const std::string &json_string) {
    return get_int_field_value(json_string, "md_query_count");
  }

  int get_update_attributes_count(const std::string &json_string) {
    return get_int_field_value(json_string, "update_attributes_count");
  }

  int get_update_last_check_in_count(const std::string &json_string) {
    return get_int_field_value(json_string, "update_last_check_in_count");
  }

  bool wait_metadata_read(const ProcessWrapper &router,
                          const std::chrono::milliseconds timeout) {
    const std::string needle = "Potential changes detected in cluster";

    return wait_log_contains(router, needle, timeout);
  }

  auto &launch_router(const std::string &metadata_cache_section,
                      const std::string &routing_section,
                      std::vector<uint16_t> metadata_server_ports,
                      const int expected_exitcode,
                      std::chrono::milliseconds wait_for_notify_ready = 30s) {
    auto default_section = get_DEFAULT_defaults();
    state_file_ = create_state_file(
        get_test_temp_dir_name(),
        create_state_file_content("uuid", "", metadata_server_ports, 0));
    init_keyring(default_section, get_test_temp_dir_name());
    default_section["dynamic_state"] = state_file_;

    // launch the router
    const std::string conf_file = create_config_file(
        get_test_temp_dir_name(), metadata_cache_section + routing_section,
        &default_section);
    auto &router =
        ProcessManager::launch_router({"-c", conf_file}, expected_exitcode,
                                      true, false, wait_for_notify_ready);

    return router;
  }

  void check_log_contains(ProcessWrapper &router,
                          const std::string &expected_string,
                          size_t expected_occurences) {
    const std::string log_content = router.get_logfile_content();
    EXPECT_EQ(expected_occurences,
              count_str_occurences(log_content, expected_string))
        << log_content;
  }

  std::string state_file_;
  const std::string router_metadata_username{"mysql_router1_user"};
};

struct MetadataTTLTestParams {
  // mock_server trace file
  std::string tracefile;
  // additional info about the testcase that gets printed by the gtest in the
  // results
  std::string description;
  // the type of the cluster GR or AR
  ClusterType cluster_type;
  // ttl value we want to set (floating point decimal in seconds)
  std::string ttl;
  // what is the minimal expected period between the updates
  std::chrono::milliseconds ttl_expected_min;
  // what is the maximal expected period between the updates
  std::chrono::milliseconds ttl_expected_max;

  MetadataTTLTestParams(std::string tracefile_, std::string description_,
                        ClusterType cluster_type_, std::string ttl_ = "0.5",
                        std::chrono::milliseconds ttl_expected_min_ = 0ms,
                        std::chrono::milliseconds ttl_expected_max_ = 0ms)
      : tracefile(std::move(tracefile_)),
        description(std::move(description_)),
        cluster_type(cluster_type_),
        ttl(std::move(ttl_)),
        ttl_expected_min(ttl_expected_min_),
        ttl_expected_max(ttl_expected_max_) {}
};

auto get_test_description(
    const ::testing::TestParamInfo<MetadataTTLTestParams> &info) {
  return info.param.description;
}

std::ostream &operator<<(std::ostream &os, const MetadataTTLTestParams &param) {
  return os << "(" << param.ttl << "s not in the range ["
            << param.ttl_expected_min.count() << "ms,"
            << param.ttl_expected_max.count() << "ms])";
}

namespace std {

template <class T, class R>
std::ostream &operator<<(std::ostream &os,
                         const std::chrono::duration<T, R> &duration) {
  return os << std::chrono::duration_cast<std::chrono::milliseconds>(duration)
                   .count()
            << "ms";
}

}  // namespace std

/**
 * @test Checks that the quarantine works as expected with metadata-cache
 * updates
 */
TEST_F(MetadataChacheTTLTest, Quarantine) {
  std::vector<uint16_t> classic_ports, http_ports;
  std::vector<ProcessWrapper *> cluster_nodes;

  const size_t kClusterNodes = 2;
  for (size_t i = 0; i < kClusterNodes; ++i) {
    classic_ports.push_back(port_pool_.get_next_available());
    http_ports.push_back(port_pool_.get_next_available());
  }
  const std::string json_metadata =
      get_data_dir().join("metadata_dynamic_nodes_v2_gr.js").str();

  for (size_t i = 0; i < kClusterNodes; ++i) {
    cluster_nodes.push_back(&launch_mysql_server_mock(
        json_metadata, classic_ports[i], EXIT_SUCCESS, false, http_ports[i]));
    set_mock_metadata(http_ports[i], "uuid",
                      classic_ports_to_gr_nodes(classic_ports), 0,
                      classic_ports_to_cluster_nodes(classic_ports));
  }

  const auto router_ro_port = port_pool_.get_next_available();
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V2, "0.2");
  const std::string routing_rw = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const std::string routing_ro = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin", "", "ro");

  auto &router = launch_router(metadata_cache_section, routing_rw + routing_ro,
                               classic_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);
  EXPECT_TRUE(wait_for_transaction_count_increase(http_ports[0], 2));
  make_new_connection_ok(router_ro_port, classic_ports[1]);

  SCOPED_TRACE(
      "// kill the cluster RO node and wait for it to be added to quarantine");
  EXPECT_NO_THROW(cluster_nodes[1]->kill());
  check_exit_code(*cluster_nodes[1], EXIT_SUCCESS, 5s);

  SCOPED_TRACE("// connect and trigger a quarantine");
  verify_new_connection_fails(router_ro_port);
  EXPECT_TRUE(wait_log_contains(
      router,
      "add destination '127.0.0.1:" + std::to_string(classic_ports[1]) +
          "' to quarantine",
      1s));

  SCOPED_TRACE("// bring back the cluster node");
  cluster_nodes[1] = &launch_mysql_server_mock(
      json_metadata, classic_ports[1], EXIT_SUCCESS, false, http_ports[1]);
  set_mock_metadata(http_ports[1], "uuid",
                    classic_ports_to_gr_nodes(classic_ports), 0,
                    classic_ports_to_cluster_nodes(classic_ports));

  SCOPED_TRACE("// .. and wait for it to be cleared by the quarantine");
  EXPECT_TRUE(wait_log_contains(
      router,
      "Destination candidate '127.0.0.1:" + std::to_string(classic_ports[1]) +
          "' is available, remove it from quarantine",
      10s));
}

class MetadataChacheTTLTestParam
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

MATCHER_P2(IsBetween, a, b,
           std::string(negation ? "isn't" : "is") + " between " +
               PrintToString(a) + " and " + PrintToString(b)) {
  return a <= arg && arg <= b;
}

TEST_P(MetadataChacheTTLTestParam, CheckTTLValid) {
  auto test_params = GetParam();

  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join(test_params.tracefile).str();

  /*auto &metadata_server = */ launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(test_params.cluster_type, test_params.ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {md_server_port}, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // the remaining is too time-dependent to hope it will pass with VALGRIND
  if (getenv("WITH_VALGRIND")) {
    return;
  }

  SCOPED_TRACE("// Wait for the initial metadata refresh to end");
  const auto first_refresh_stop_timestamp =
      get_log_timestamp(router.get_logfile_path(),
                        ".*Finished refreshing the cluster metadata.*", 1, 2s);
  if (!first_refresh_stop_timestamp) {
    FAIL() << "Did not find first metadata refresh end log in the logfile.\n"
           << router.get_logfile_content();
  }

  SCOPED_TRACE("// Wait for the second metadata refresh to start");
  const auto second_refresh_start_timestamp = get_log_timestamp(
      router.get_logfile_path(), ".*Started refreshing the cluster metadata.*",
      2, test_params.ttl_expected_max + 1s);
  if (!second_refresh_start_timestamp) {
    FAIL() << "Did not find second metadata refresh start log in the logfile.\n"
           << router.get_logfile_content();
  }

  SCOPED_TRACE(
      "// Check if the time passed in between falls into expected range");
  const auto ttl = second_refresh_start_timestamp.value() -
                   first_refresh_stop_timestamp.value();

  // The upper bound can't be tested reliably in PB2 environment
  // EXPECT_THAT(ttl, IsBetween(test_params.ttl_expected_min,
  //                            test_params.ttl_expected_max));

  EXPECT_GE(ttl, test_params.ttl_expected_min);
}

INSTANTIATE_TEST_SUITE_P(
    CheckTTLIsUsedCorrectly, MetadataChacheTTLTestParam,
    ::testing::Values(
        MetadataTTLTestParams("metadata_1_node_repeat_v2_gr.js", "0_gr_v2",
                              ClusterType::GR_V2, "0.2", 150ms, 490ms),
        MetadataTTLTestParams("metadata_1_node_repeat.js", "0_gr",
                              ClusterType::GR_V1, "0.2", 150ms, 490ms),
        MetadataTTLTestParams("metadata_1_node_repeat_v2_ar.js", "0_ar_v2",
                              ClusterType::RS_V2, "0.2", 150ms, 490ms),

        MetadataTTLTestParams("metadata_1_node_repeat_v2_gr.js", "1_gr_v2",
                              ClusterType::GR_V2, "1", 700ms, 1800ms),
        MetadataTTLTestParams("metadata_1_node_repeat.js", "1_gr",
                              ClusterType::GR_V1, "1", 700ms, 1800ms),
        MetadataTTLTestParams("metadata_1_node_repeat_v2_ar.js", "1_ar_v2",
                              ClusterType::RS_V2, "1", 700ms, 1800ms),

        // check that default is 0.5 if not provided:
        MetadataTTLTestParams("metadata_1_node_repeat_v2_gr.js", "2_gr_v2",
                              ClusterType::GR_V2, "", 450ms, 900ms),
        MetadataTTLTestParams("metadata_1_node_repeat.js", "2_gr",
                              ClusterType::GR_V1, "", 450ms, 900ms),
        MetadataTTLTestParams("metadata_1_node_repeat_v2_ar.js", "2_ar_v2",
                              ClusterType::RS_V2, "", 450ms, 900ms),

        // check that for 0 the delay between the refresh is very short
        MetadataTTLTestParams("metadata_1_node_repeat_v2_gr.js", "3_gr_v2",
                              ClusterType::GR_V2, "0", 0ms, 450ms),
        MetadataTTLTestParams("metadata_1_node_repeat.js", "3_gr",
                              ClusterType::GR_V1, "0", 0ms, 450ms),
        MetadataTTLTestParams("metadata_1_node_repeat_v2_ar.js", "3_ar_v2",
                              ClusterType::RS_V2, "0", 0ms, 450ms)),
    get_test_description);

class MetadataChacheTTLTestParamInvalid
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(MetadataChacheTTLTestParamInvalid, CheckTTLInvalid) {
  auto test_params = GetParam();

  // launch the server mock (it's our metadata server and single cluster node)
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  /*auto &metadata_server =*/launch_mysql_server_mock(
      json_metadata, md_server_port, false, md_server_http_port);

  // launch the router with metadata-cache configuration
  const auto router_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(test_params.cluster_type, test_params.ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {md_server_port}, EXIT_FAILURE,
                               /*wait_for_notify_ready=*/-1s);

  check_exit_code(router, EXIT_FAILURE);
  EXPECT_THAT(router.exit_code(), testing::Ne(0));
  EXPECT_TRUE(wait_log_contains(router,
                                "Configuration error: option ttl in "
                                "\\[metadata_cache:bootstrap\\] needs value "
                                "between 0 and 3600 inclusive",
                                500ms));
}

INSTANTIATE_TEST_SUITE_P(
    CheckInvalidTTLRefusesStart, MetadataChacheTTLTestParamInvalid,
    ::testing::Values(
        MetadataTTLTestParams("metadata_1_node_repeat_gr_v2.js", "0_all",
                              ClusterType::GR_V2, "-0.001"),
        MetadataTTLTestParams("metadata_1_node_repeat_gr_v2.js", "1_all",
                              ClusterType::GR_V2, "3600.001"),
        MetadataTTLTestParams("metadata_1_node_repeat_gr_v2.js", "2_all",
                              ClusterType::GR_V2, "INVALID"),
        MetadataTTLTestParams("metadata_1_node_repeat_gr_v2.js", "3_all",
                              ClusterType::GR_V2, "1,1")),
    get_test_description);

class MetadataChacheTTLTestInstanceListUnordered
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

/**
 * @test Checks that when for some reason the metadata server starts
 *       returning the information about the cluster nodes in different order we
 *       will not treat this as a change (Bug#29264764).
 */
TEST_P(MetadataChacheTTLTestInstanceListUnordered, InstancesListUnordered) {
  const std::string kGroupID = "uuid";

  SCOPED_TRACE("// launch 2 server mocks");
  std::vector<ProcessWrapper *> nodes;
  std::vector<uint16_t> node_classic_ports;
  std::vector<uint16_t> node_http_ports;
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  using ClusterNode = ::ClusterNode;
  std::vector<GRNode> gr_nodes;
  std::vector<ClusterNode> cluster_nodes;
  for (size_t i = 0; i < 2; ++i) {
    node_classic_ports.push_back(port_pool_.get_next_available());
    node_http_ports.push_back(port_pool_.get_next_available());

    nodes.push_back(
        &launch_mysql_server_mock(json_metadata, node_classic_ports[i],
                                  EXIT_SUCCESS, false, node_http_ports[i]));
    gr_nodes.emplace_back(node_classic_ports[i],
                          "uuid-" + std::to_string(i + 1));
    cluster_nodes.emplace_back(node_classic_ports[i],
                               "uuid-" + std::to_string(i + 1));
  }

  for (auto [i, http_port] : stdx::views::enumerate(node_http_ports)) {
    ::set_mock_metadata(http_port, kGroupID, gr_nodes, i, cluster_nodes);
  }

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {node_classic_ports}, EXIT_SUCCESS, 5s);

  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0]));

  SCOPED_TRACE("// instruct the mocks to return nodes in reverse order");
  const std::vector<GRNode> gr_nodes_reversed(gr_nodes.rbegin(),
                                              gr_nodes.rend());
  const std::vector<ClusterNode> cluster_nodes_reversed(cluster_nodes.rbegin(),
                                                        cluster_nodes.rend());
  for (auto [i, http_port] : stdx::views::enumerate(node_http_ports)) {
    ::set_mock_metadata(http_port, kGroupID, gr_nodes_reversed, i,
                        cluster_nodes_reversed, 1);
  }

  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0]));

  SCOPED_TRACE("// check it is not treated as a change");
  const std::string needle = "Potential changes detected in cluster";
  const std::string log_content = router.get_logfile_content();

  // 1 is expected, that comes from the initial reading of the metadata
  EXPECT_EQ(1, count_str_occurences(log_content, needle)) << log_content;
}

INSTANTIATE_TEST_SUITE_P(
    InstancesListUnordered, MetadataChacheTTLTestInstanceListUnordered,
    ::testing::Values(
        MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                              "unordered_gr_v2", ClusterType::GR_V2, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes.js", "unordered_gr",
                              ClusterType::GR_V1, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                              "unordered_ar_v2", ClusterType::RS_V2, "0.1")),
    get_test_description);

class MetadataChacheTTLTestInvalidMysqlXPort
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

/**
 * @test Check that invalid mysqlx port in the metadata does not cause the node
 * to be discarded for the classic protocol connections (Bug#30617645)
 */
TEST_P(MetadataChacheTTLTestInvalidMysqlXPort, InvalidMysqlXPort) {
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  SCOPED_TRACE("// single node cluster is fine for this test");
  const uint16_t node_classic_port{port_pool_.get_next_available()};
  const uint16_t node_http_port{port_pool_.get_next_available()};
  const uint32_t kInvalidPort{76000};

  /*auto &cluster_node = */ launch_mysql_server_mock(
      json_metadata, node_classic_port, EXIT_SUCCESS, false, node_http_port);

  SCOPED_TRACE(
      "// let the metadata for our single node report invalid mysqlx port");
  set_mock_metadata(node_http_port, "uuid", {{node_classic_port}}, 0,
                    {{node_classic_port, kInvalidPort}}, 0, 0, false,
                    "127.0.0.1");

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {node_classic_port}, EXIT_SUCCESS, 5s);

  // TODO: still needed?
  ASSERT_TRUE(wait_metadata_read(router, 5s)) << router.get_full_output();

  SCOPED_TRACE(
      "// Even though the metadata contains invalid mysqlx port we still "
      "should be able to connect on the classic port");
  EXPECT_TRUE(wait_for_port_ready(router_port));
  MySQLSession client;
  ASSERT_NO_FATAL_FAILURE(
      client.connect("127.0.0.1", router_port, "username", "password", "", ""));
}

INSTANTIATE_TEST_SUITE_P(
    InvalidMysqlXPort, MetadataChacheTTLTestInvalidMysqlXPort,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "gr_v2", ClusterType::GR_V2, "5"),
                      MetadataTTLTestParams("metadata_dynamic_nodes.js", "gr",
                                            ClusterType::GR_V1, "5"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "ar_v2", ClusterType::RS_V2, "5")),
    get_test_description);

/**
 * @test Checks that the router operates smoothly when the metadata version has
 * changed between the metadata refreshes.
 */
TEST_F(MetadataChacheTTLTest, CheckMetadataUpgradeBetweenTTLs) {
  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join("metadata_1_node_repeat_metadatada_upgrade.js").str();

  /*auto &metadata_server = */ launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();

  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V1, "0.5");
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {md_server_port}, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // keep the router running for a while and change the metadata version
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 2));

  MockServerRestClient(md_server_http_port)
      .set_globals("{\"new_metadata\" : 1}");

  // let the router run a bit more
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 2));

  const std::string log_content = router.get_logfile_content();

  SCOPED_TRACE(
      "// check that the router really saw the version upgrade at some point");
  std::string needle =
      "Metadata version change was discovered. New metadata version is 2.0.0";
  EXPECT_GE(1, count_str_occurences(log_content, needle));

  SCOPED_TRACE(
      "// there should be no cluster change reported caused by the version "
      "upgrade");
  needle = "Potential changes detected in cluster";
  // 1 is expected, that comes from the initial reading of the metadata
  EXPECT_EQ(1, count_str_occurences(log_content, needle));

  // router should exit noramlly
  ASSERT_THAT(router.kill(), testing::Eq(0));
}

class CheckRouterInfoUpdatesTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

/**
 * @test Checks that the Router updates the static configuration information in
 * the metadata once when it starts and that the periodic updates are done every
 * 10th metadata refresh when working with standalone Cluster (that is not a
 * part of a ClusterSet).
 */
TEST_P(CheckRouterInfoUpdatesTest, CheckRouterInfoUpdates) {
  const auto router_port = port_pool_.get_next_available();
  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  /*auto &metadata_server = */ launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);

  SCOPED_TRACE(
      "// let's tell the mock which attributes it should expect so that it "
      "does the strict sql matching for us");
  auto globals =
      mock_GR_metadata_as_json("uuid", {md_server_port}, 0, {md_server_port});
  JsonAllocator allocator;
  globals.AddMember("router_version", MYSQL_ROUTER_VERSION, allocator);
  globals.AddMember("router_rw_classic_port", router_port, allocator);
  globals.AddMember("router_metadata_user",
                    JsonValue(router_metadata_username.c_str(),
                              router_metadata_username.length(), allocator),
                    allocator);
  const auto globals_str = json_to_string(globals);
  MockServerRestClient(md_server_http_port).set_globals(globals_str);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");

  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  launch_router(metadata_cache_section, routing_section, {md_server_port},
                EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  SCOPED_TRACE("// let the router run for at least 10 metadata refresh cycles");
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 12));

  SCOPED_TRACE("// we still expect the version to be only set once");
  std::string server_globals =
      MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  const int attributes_upd_count = get_update_attributes_count(server_globals);
  EXPECT_EQ(1, attributes_upd_count);

  SCOPED_TRACE(
      "// Let's check if the first query is starting a trasaction and the "
      "second checking the version");

  const auto queries = get_array_field_value(server_globals, "queries");
  EXPECT_EQ(4u, queries.size()) << server_globals;

  EXPECT_STREQ(
      "SET @@SESSION.autocommit=1, @@SESSION.character_set_client=utf8, "
      "@@SESSION.character_set_results=utf8, "
      "@@SESSION.character_set_connection=utf8, "
      "@@SESSION.sql_mode='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_"
      "DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION', "
      "@@SESSION.optimizer_switch='derived_merge=on'",
      queries.at(0).c_str());
  EXPECT_STREQ("SET @@SESSION.group_replication_consistency='EVENTUAL'",
               queries.at(1).c_str());
  EXPECT_STREQ("START TRANSACTION", queries.at(2).c_str());
  EXPECT_STREQ("SELECT * FROM mysql_innodb_cluster_metadata.schema_version",
               queries.at(3).c_str());

  if (GetParam().cluster_type != ClusterType::GR_V1) {
    SCOPED_TRACE(
        "// last_check_in should be attempted at least twice (first update is "
        "done on start)");
    std::string server_globals =
        MockServerRestClient(md_server_http_port).get_globals_as_json_string();
    const int last_check_in_upd_count =
        get_update_last_check_in_count(server_globals);
    EXPECT_GE(2, last_check_in_upd_count);
  }
}

INSTANTIATE_TEST_SUITE_P(
    CheckRouterInfoUpdates, CheckRouterInfoUpdatesTest,
    ::testing::Values(
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update.js",
                              "router_version_update_once_gr_v1",
                              ClusterType::GR_V1, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_gr.js",
                              "router_version_update_once_gr_v2",
                              ClusterType::GR_V2, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_ar.js",
                              "router_version_update_once_ar_v2",
                              ClusterType::RS_V2, "0.1")),
    get_test_description);

/**
 * @test Verify that when the Router was bootstrapped against the Cluster while
 * it was a standalone Cluster and now it is part of a ClusterSet, Router checks
 * v2_cs_router_options for periodic updates frequency
 */
TEST_F(MetadataChacheTTLTest, CheckRouterInfoUpdatesClusterPartOfCS) {
  const auto router_port = port_pool_.get_next_available();
  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir()
          .join("metadata_dynamic_nodes_version_update_v2_gr.js")
          .str();

  /*auto &metadata_server = */ launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);

  SCOPED_TRACE(
      "// let's tell the mock which attributes it should expect so that it "
      "does the strict sql matching for us");
  auto globals =
      mock_GR_metadata_as_json("uuid", {md_server_port}, 0, {md_server_port});
  JsonAllocator allocator;
  globals.AddMember("router_version", MYSQL_ROUTER_VERSION, allocator);
  globals.AddMember("router_rw_classic_port", router_port, allocator);
  globals.AddMember("router_metadata_user",
                    JsonValue(router_metadata_username.c_str(),
                              router_metadata_username.length(), allocator),
                    allocator);

  // instrument the metadata in a way that shows that we bootstrapped once the
  // Cluster was standalone but now it is part of a ClusterSet
  globals.AddMember("bootstrap_target_type", "cluster", allocator);
  globals.AddMember("clusterset_present", 1, allocator);
  const auto globals_str = json_to_string(globals);
  MockServerRestClient(md_server_http_port).set_globals(globals_str);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");

  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V2, "0.1");
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  launch_router(metadata_cache_section, routing_section, {md_server_port},
                EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  SCOPED_TRACE("// let the router run for at least 10 metadata refresh cycles");
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 12));

  SCOPED_TRACE("// we expect the version to be only set once");
  std::string server_globals =
      MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  const int attributes_upd_count = get_update_attributes_count(server_globals);
  EXPECT_EQ(1, attributes_upd_count);

  // We were bootstrapped once the Cluster was standalone Cluster. Now it is
  // part of the ClusterSet. Even though we keep using the Cluster as a
  // standalone Cluster, we make an expection when it comes to periodic updates.
  // We don't want to do them unless the frequency is explicitly set in the
  // v2_cs_router_options.
  const int last_check_in_upd_count =
      get_update_last_check_in_count(server_globals);

  // since the frequency is not set in v2_cs_router_options we do not expect any
  // periodic updates
  EXPECT_EQ(0, last_check_in_upd_count);
}

/**
 * @test verify if appropriate warning messages are logged when the Cluster has
 * deprecated metadata version.
 */
TEST_F(MetadataChacheTTLTest, LogWarningWhenMetadataIsDeprecated) {
  RecordProperty("Worklog", "15876");
  RecordProperty("RequirementId", "FR1");
  RecordProperty("Description",
                 "Checks that the Router logs a deprecation warning for "
                 "metadata version 1.x exactly once per each metadata server");
  // create a 2-node cluster
  const std::vector<uint16_t> cluster_nodes_ports{
      port_pool_.get_next_available(), port_pool_.get_next_available()};
  const std::vector<uint16_t> cluster_nodes_http_ports{
      port_pool_.get_next_available(), port_pool_.get_next_available()};
  for (size_t i = 0; i < cluster_nodes_ports.size(); ++i) {
    const auto classic_port = cluster_nodes_ports[i];
    const auto http_port = cluster_nodes_http_ports[i];
    launch_mysql_server_mock(
        get_data_dir().join("metadata_dynamic_nodes.js").str(), classic_port,
        EXIT_SUCCESS, false, http_port);
    EXPECT_TRUE(MockServerRestClient(http_port).wait_for_rest_endpoint_ready());
    ::set_mock_metadata(http_port, "uuid",
                        classic_ports_to_gr_nodes(cluster_nodes_ports), 1,
                        classic_ports_to_cluster_nodes(cluster_nodes_ports));
  }
  // launch the router with metadata-cache configuration
  const auto router_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V2, "0.1");
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               cluster_nodes_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);
  // let the Router run for a several metadata refresh cycles
  wait_for_transaction_count_increase(cluster_nodes_http_ports[0], 6);
  // check that warning about deprecated metadata was logged once (we only
  // connected to a single metadata server as it is a part of quorum)
  check_log_contains(
      router,
      "Instance '127.0.0.1:" + std::to_string(cluster_nodes_ports[0]) +
          "': The target Cluster's Metadata version ('1.0.2') is "
          "deprecated. Please use the latest MySQL Shell to upgrade it using "
          "'dba.upgradeMetadata()'.",
      1);
}

class PermissionErrorOnVersionUpdateTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(PermissionErrorOnVersionUpdateTest, PermissionErrorOnAttributesUpdate) {
  const auto router_port = port_pool_.get_next_available();
  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  /*auto &metadata_server =*/launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);

  SCOPED_TRACE(
      "// let's tell the mock which attributes it should expect so that it "
      "does the strict sql matching for us, also tell it to issue the "
      "permission error on the update attempt");
  auto globals =
      mock_GR_metadata_as_json("uuid", {md_server_port}, 0, {md_server_port});
  JsonAllocator allocator;
  globals.AddMember("router_version", MYSQL_ROUTER_VERSION, allocator);
  globals.AddMember("router_rw_classic_port", router_port, allocator);
  globals.AddMember("router_metadata_user",
                    JsonValue(router_metadata_username.c_str(),
                              router_metadata_username.length(), allocator),
                    allocator);

  globals.AddMember("perm_error_on_version_update", 1, allocator);
  const auto globals_str = json_to_string(globals);
  MockServerRestClient(md_server_http_port).set_globals(globals_str);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");

  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {md_server_port}, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  SCOPED_TRACE(
      "// wait for several Router transactions on the metadata server");
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 6));

  SCOPED_TRACE(
      "// we expect the error trying to update the attributes in the log "
      "exactly once");
  const std::string log_content = router.get_logfile_content();
  const std::string needle =
      "Make sure to follow the correct steps to upgrade your metadata.\n"
      "Run the dba.upgradeMetadata() then launch the new Router version "
      "when prompted";
  EXPECT_EQ(1, count_str_occurences(log_content, needle)) << log_content;

  SCOPED_TRACE(
      "// we expect that the router attempted to update the continuously "
      "because of the missing access rights error");
  std::string server_globals =
      MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  const int attributes_upd_count = get_update_attributes_count(server_globals);
  EXPECT_GT(attributes_upd_count, 1);

  SCOPED_TRACE(
      "// It should still not be fatal, the router should accept the "
      "connections to the cluster");
  MySQLSession client;
  ASSERT_NO_FATAL_FAILURE(
      client.connect("127.0.0.1", router_port, "username", "password", "", ""));
}

INSTANTIATE_TEST_SUITE_P(
    PermissionErrorOnVersionUpdate, PermissionErrorOnVersionUpdateTest,
    ::testing::Values(
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update.js",
                              "router_version_update_fail_on_perm_gr_v1",
                              ClusterType::GR_V1, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_gr.js",
                              "router_version_update_fail_on_perm_gr_v2",
                              ClusterType::GR_V2, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_ar.js",
                              "router_version_update_fail_on_perm_ar_v2",
                              ClusterType::RS_V2, "0.1")),
    get_test_description);

class UpgradeInProgressTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(UpgradeInProgressTest, UpgradeInProgress) {
  SCOPED_TRACE(
      "// launch the server mock (it's our metadata server and single cluster "
      "node)");
  auto md_server_port = port_pool_.get_next_available();
  auto md_server_http_port = port_pool_.get_next_available();
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  /*auto &metadata_server = */ launch_mysql_server_mock(
      json_metadata, md_server_port, EXIT_SUCCESS, false, md_server_http_port);
  set_mock_metadata(md_server_http_port, "uuid", {md_server_port}, 0,
                    {md_server_port});

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();

  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");
  auto &router = launch_router(metadata_cache_section, routing_section,
                               {md_server_port}, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);
  EXPECT_TRUE(wait_for_port_used(router_port));

  SCOPED_TRACE("// let us make some user connection via the router port");
  auto client = make_new_connection_ok(router_port, md_server_port);

  SCOPED_TRACE("// let's mimmic start of the metadata update now");
  auto globals =
      mock_GR_metadata_as_json("uuid", {md_server_port}, 0, {md_server_port});
  JsonAllocator allocator;
  globals.AddMember("upgrade_in_progress", 1, allocator);
  globals.AddMember("md_query_count", 0, allocator);
  const auto globals_str = json_to_string(globals);
  MockServerRestClient(md_server_http_port).set_globals(globals_str);

  SCOPED_TRACE(
      "// Wait some more and read the metadata update count once more to avoid "
      "race condition.");
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 2));
  MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  std::string server_globals =
      MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  int metadata_upd_count = get_ttl_queries_count(server_globals);

  SCOPED_TRACE(
      "// Now wait another 3 ttl periods, since the metadata update is in "
      "progress we do not expect the increased number of metadata queries "
      "after that period");
  EXPECT_TRUE(wait_for_transaction_count_increase(md_server_http_port, 3));
  server_globals =
      MockServerRestClient(md_server_http_port).get_globals_as_json_string();
  const int metadata_upd_count2 = get_ttl_queries_count(server_globals);
  EXPECT_EQ(metadata_upd_count, metadata_upd_count2);

  SCOPED_TRACE(
      "// Even though the upgrade is in progress the existing connection "
      "should still be active.");
  verify_existing_connection_ok(client.get());

  SCOPED_TRACE("// Also we should be able to create a new conenction.");
  MySQLSession client2;
  ASSERT_NO_FATAL_FAILURE(client2.connect("127.0.0.1", router_port, "username",
                                          "password", "", ""));

  SCOPED_TRACE("// Info about the update should be logged.");
  const std::string log_content = router.get_logfile_content();
  ASSERT_TRUE(log_content.find("Cluster metadata upgrade in progress, aborting "
                               "the metada refresh") != std::string::npos);
}

INSTANTIATE_TEST_SUITE_P(
    UpgradeInProgress, UpgradeInProgressTest,
    ::testing::Values(
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update.js",
                              "metadata_upgrade_in_progress_gr_v1",
                              ClusterType::GR_V1, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_gr.js",
                              "metadata_upgrade_in_progress_gr_v2",
                              ClusterType::GR_V2, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_version_update_v2_ar.js",
                              "metadata_upgrade_in_progress_ar_v2",
                              ClusterType::RS_V2, "0.1")),
    get_test_description);

/**
 * @test
 * Verify that when the cluster node returns empty dataset from the
 * v2_this_instance view, the router fails over to the other known nodes to try
 * to read the metadata (BUG#30733189)
 */
class NodeRemovedTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(NodeRemovedTest, NodeRemoved) {
  const size_t NUM_NODES = 2;
  std::vector<uint16_t> node_ports, node_http_ports;
  std::vector<ProcessWrapper *> cluster_nodes;

  SCOPED_TRACE("// launch cluster with 2 nodes");
  const std::string json_metadata =
      get_data_dir().join(GetParam().tracefile).str();

  for (size_t i = 0; i < NUM_NODES; ++i) {
    node_ports.push_back(port_pool_.get_next_available());
    node_http_ports.push_back(port_pool_.get_next_available());
  }

  for (size_t i = 0; i < NUM_NODES; ++i) {
    cluster_nodes.push_back(&launch_mysql_server_mock(
        json_metadata, node_ports[i], EXIT_SUCCESS, false, node_http_ports[i]));
    set_mock_metadata(node_http_ports[i], "uuid",
                      classic_ports_to_gr_nodes(node_ports), i,
                      classic_ports_to_cluster_nodes(node_ports));
  }

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const auto router_port = port_pool_.get_next_available();

  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, GetParam().ttl);
  const std::string routing_section = get_metadata_cache_routing_section(
      router_port, "PRIMARY", "first-available");

  launch_router(metadata_cache_section, routing_section, node_ports,
                EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  SCOPED_TRACE(
      "// Make a connection to the primary, it should be the first node");
  { /*auto client =*/
    make_new_connection_ok(router_port, node_ports[0]);
  }

  SCOPED_TRACE(
      "// Mimic the removal of the first node, this_instance view on this node "
      "should return empty dataset");
  auto globals =
      mock_GR_metadata_as_json("uuid", classic_ports_to_gr_nodes(node_ports), 0,
                               classic_ports_to_cluster_nodes(node_ports));
  JsonAllocator allocator;
  globals.AddMember("cluster_type", "", allocator);
  const auto globals_str = json_to_string(globals);
  MockServerRestClient(node_http_ports[0]).set_globals(globals_str);

  SCOPED_TRACE(
      "// Tell the second node that it is a new Primary and the only member of "
      "the cluster");
  set_mock_metadata(node_http_ports[1], "uuid", {node_ports[1]}, 0,
                    {node_ports[1]});

  SCOPED_TRACE(
      "// Connect to the router primary port, the connection should be ok and "
      "we should be connected to the new primary now");
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[1], 2));

  SCOPED_TRACE("// let us make some user connection via the router port");
  /*auto client =*/make_new_connection_ok(router_port, node_ports[1]);
}

INSTANTIATE_TEST_SUITE_P(
    NodeRemoved, NodeRemovedTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "node_removed_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "node_removed_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class NodeHiddenTest : public MetadataChacheTTLTest {
 protected:
  // MUST be 'localhost' to verify it works with hostnames and not just IP
  // addresses.
  static constexpr const char *const node_hostname{"localhost"};

  // first node is RW, all others (if any) RO
  void setup_cluster(const size_t nodes_count, const std::string &tracefile,
                     const std::vector<std::string> &nodes_attributes = {},
                     const bool no_primary = false) {
    assert(nodes_count > 0);

    const std::string json_metadata = get_data_dir().join(tracefile).str();

    for (size_t i = 0; i < nodes_count; ++i) {
      // if we are "relaunching" the cluster we want to use the same port as
      // before as router has them in the configuration
      if (node_ports.size() < nodes_count) {
        node_ports.push_back(port_pool_.get_next_available());
        node_http_ports.push_back(port_pool_.get_next_available());
      }

      cluster_nodes.push_back(
          &launch_mysql_server_mock(json_metadata, node_ports[i], EXIT_SUCCESS,
                                    false, node_http_ports[i]));
    }

    for (size_t i = 0; i < nodes_count; ++i) {
      ASSERT_NO_FATAL_FAILURE(
          check_port_ready(*cluster_nodes[i], node_ports[i]));
      ASSERT_TRUE(MockServerRestClient(node_http_ports[i])
                      .wait_for_rest_endpoint_ready());

      const auto primary_id = no_primary ? -1 : 0;
      auto cluster_nodes = classic_ports_to_cluster_nodes(node_ports);
      for (auto [i, attr] : stdx::views::enumerate(nodes_attributes)) {
        if (i < cluster_nodes.size()) {
          cluster_nodes[i].attributes = attr;
        }
      }
      set_mock_metadata(node_http_ports[i], "uuid",
                        classic_ports_to_gr_nodes(node_ports), i, cluster_nodes,
                        primary_id, 0, false, node_hostname);
    }
  }

  void setup_router(ClusterType cluster_type, const std::string &ttl,
                    const bool read_only = false) {
    const std::string metadata_cache_section =
        get_metadata_cache_section(cluster_type, ttl);
    std::string routing_rw_section{""};
    if (!read_only) {
      routing_rw_section = get_metadata_cache_routing_section(
          router_rw_port, "PRIMARY", "first-available", "", "rw");
      routing_rw_section += get_metadata_cache_routing_section(
          router_rw_x_port, "PRIMARY", "first-available", "", "x_rw", "x");
    }
    std::string routing_ro_section = get_metadata_cache_routing_section(
        router_ro_port, "SECONDARY", "round-robin", "", "ro");
    routing_ro_section += get_metadata_cache_routing_section(
        router_ro_x_port, "SECONDARY", "round-robin", "", "x_ro", "x");

    router = &launch_router(metadata_cache_section,
                            routing_rw_section + routing_ro_section, node_ports,
                            EXIT_SUCCESS,
                            /*wait_for_notify_ready=*/30s);

    ASSERT_NO_FATAL_FAILURE(
        check_port_ready(*router, read_only ? router_ro_port : router_rw_port));

    EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  }

  void set_nodes_attributes(const std::vector<std::string> &nodes_attributes,
                            const bool no_primary = false) {
    const auto primary_id = no_primary ? -1 : 0;

    auto cluster_nodes = classic_ports_to_cluster_nodes(node_ports);
    for (auto [i, attr] : stdx::views::enumerate(nodes_attributes)) {
      if (i < cluster_nodes.size()) {
        cluster_nodes[i].attributes = attr;
      }
    }

    ASSERT_NO_THROW({
      set_mock_metadata(node_http_ports[0], "uuid",
                        classic_ports_to_gr_nodes(node_ports), 0, cluster_nodes,
                        primary_id, 0, false, node_hostname);
    });

    try {
      ASSERT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 3));
    } catch (const std::exception &e) {
      FAIL() << "failed waiting for trans' count increase: " << e.what();
    };
  }

  std::vector<uint16_t> node_ports, node_http_ports;
  std::vector<ProcessWrapper *> cluster_nodes;
  ProcessWrapper *router;

  const uint16_t router_rw_port{port_pool_.get_next_available()};
  const uint16_t router_ro_port{port_pool_.get_next_available()};
  const uint16_t router_rw_x_port{port_pool_.get_next_available()};
  const uint16_t router_ro_x_port{port_pool_.get_next_available()};

 private:
  TempDirectory temp_test_dir;
  TempDirectory conf_dir{"conf"};
};

// define constexpr for sun-cc
constexpr const char *const NodeHiddenTest::node_hostname;

/**
 * @test Verifies that setting the _hidden tags in the metadata for the node is
 * handled as expected by the Router.
 *
 * WL#13787: TS_FR02_01, TS_FR02_02, TS_FR02_04
 * WL#13327: TS_R2_6
 */
class ClusterNodeHiddenTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(ClusterNodeHiddenTest, RWRONodeHidden) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  try {
    setup_cluster(3, GetParam().tracefile);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  try {
    setup_router(GetParam().cluster_type, GetParam().ttl);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// check if both RO and RW ports are used");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Make rw connection, should be ok");
  try {
    make_new_connection_ok(router_rw_port, node_ports[0]);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Configure first RO node to hidden=true");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({"", R"({"tags" : {"_hidden": true} })", ""}));

  SCOPED_TRACE("// RW and RO ports should be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Configure both RO node to hidden=true");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({"", R"({"tags" : {"_hidden": true} })",
                            R"({"tags" : {"_hidden": true} })"}));

  SCOPED_TRACE("// RO ports should not be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Unhide first RO node");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({"", R"({"tags" : {"_hidden": false} })", ""}));

  SCOPED_TRACE("// RO ports should be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Hide first RO node");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({"", R"({"tags" : {"_hidden": true} })",
                            R"({"tags" : {"_hidden": true} })"}));

  SCOPED_TRACE("// RO ports should not be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Unhide second RO node");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({"", R"({"tags" : {"_hidden": false} })",
                            R"({"tags" : {"_hidden": true} })"}));

  SCOPED_TRACE("// RO ports should be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Unhide first RO node");
  ASSERT_NO_FATAL_FAILURE({
    set_nodes_attributes({"", R"({"tags" : {"_hidden": false} })",
                          R"({"tags" : {"_hidden": false} })"});
  });

  SCOPED_TRACE("// RO ports should be used by the router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE(
      "// Configure RW node to hidden=true, "
      "disconnect_existing_sessions_when_hidden stays default which is "
      "'true'");
  ASSERT_NO_FATAL_FAILURE(set_nodes_attributes(
      {R"({"tags" : {"_hidden": true} })", R"({"tags" : {"_hidden": true} })",
       R"({"tags" : {"_hidden": true} })"}));

  SCOPED_TRACE("// RW port should be open");
  try {
    EXPECT_TRUE(wait_for_port_unused(router_rw_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_port));
    EXPECT_TRUE(wait_for_port_unused(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Making new connection should not be possible");
  try {
    verify_new_connection_fails(router_rw_port);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Configure RW node back to hidden=false");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({R"({"tags" : {"_hidden": false} })", "", ""}));

  SCOPED_TRACE("// RW port should be again used by the Router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Making new connection should be possible again");
  try {
    make_new_connection_ok(router_rw_port, node_ports[0]);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Configure RW node again to hidden=true");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({R"({"tags" : {"_hidden": true} })", "", ""}));

  try {
    EXPECT_TRUE(wait_for_port_unused(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_unused(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Making new connection should not be possible");
  try {
    verify_new_connection_fails(router_rw_port);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }

  SCOPED_TRACE("// Configure RW node back to hidden=false");
  ASSERT_NO_FATAL_FAILURE(
      set_nodes_attributes({R"({"tags" : {"_hidden": false} })", "", ""}));

  SCOPED_TRACE("// RW port should be again used by the Router");
  try {
    EXPECT_TRUE(wait_for_port_used(router_rw_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_port));
    EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
    EXPECT_TRUE(wait_for_port_used(router_ro_x_port));
    SCOPED_TRACE("// Making new connection should be possible again");
    make_new_connection_ok(router_rw_port, node_ports[0]);
  } catch (const std::exception &e) {
    FAIL() << e.what();
  }
}

TEST_P(ClusterNodeHiddenTest, RWNodeHidden) {
  SCOPED_TRACE("// launch cluster with only 1 RW node");
  setup_cluster(1, GetParam().tracefile);
  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);

  SCOPED_TRACE("// RW socket is listening");
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));
  EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));

  SCOPED_TRACE("// Hide RW node");
  set_nodes_attributes({R"({"tags" : {"_hidden": true} })"});
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));
  EXPECT_TRUE(wait_for_port_unused(router_rw_x_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));

  SCOPED_TRACE("// Unhide RW node");
  set_nodes_attributes({R"({"tags" : {"_hidden": false} })"});
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));
  EXPECT_TRUE(wait_for_port_used(router_rw_x_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_x_port));
}

INSTANTIATE_TEST_SUITE_P(
    ClusterNodeHidden, ClusterNodeHiddenTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "node_hidden_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "node_hidden_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

/**
 * @test Verifies that setting the _disconnect_existing_sessions_when_hidden
 *       tags back and forth in the metadata for the node is handled as expected
 *        by the Router.
 *
 *  TS_FR02_03, TS_FR04_01
 */
class RWNodeHiddenDontDisconnectToggleTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(RWNodeHiddenDontDisconnectToggleTest, RWNodeHiddenDontDisconnectToggle) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  setup_cluster(3, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0]));

  // test tags: {hidden, disconnect}
  {
    SCOPED_TRACE("// Make rw connection, should be ok");
    auto rw_con_1 = make_new_connection_ok(router_rw_port, node_ports[0]);

    SCOPED_TRACE(
        "// Configure the first RW node to hidden=true, "
        "set disconnect_existing_sessions_when_hidden stays default which is "
        "true");
    set_nodes_attributes({R"({"tags" : {"_hidden": true} })", "", ""});

    SCOPED_TRACE("// The connection should get dropped");
    verify_existing_connection_dropped(rw_con_1.get());
  }

  // reset test (clear hidden flag)
  {
    SCOPED_TRACE(
        "// Unhide the node, "
        "set disconnect_existing_sessions_when_hidden to false");
    set_nodes_attributes(
        {R"({"tags" : {"_hidden": false, "_disconnect_existing_sessions_when_hidden": false} })",
         "", ""});
  }

  // test tags: {hidden}, then {hidden, disconnect}
  {
    // test tags: {hidden}

    SCOPED_TRACE("// Make rw connection, should be ok");
    auto rw_con_2 = make_new_connection_ok(router_rw_port, node_ports[0]);

    SCOPED_TRACE(
        "// Now configure the first RW node to hidden=true, "
        "disconnect_existing_sessions_when_hidden stays false");
    set_nodes_attributes(
        {R"({"tags" : {"_hidden": true, "_disconnect_existing_sessions_when_hidden": false} })",
         "", ""});

    SCOPED_TRACE("// The existing connection should be ok");
    verify_existing_connection_ok(rw_con_2.get(), node_ports[0]);

    // reset test (clear hidden flag); connection should still be alive
    // therefore we can reuse it for the next test
    SCOPED_TRACE("// Set disconnect_existing_sessions_when_hidden=true");
    set_nodes_attributes(
        {R"({"tags" : {"_disconnect_existing_sessions_when_hidden": true} })",
         "", ""});

    // test tags: {hidden, disconnect}

    SCOPED_TRACE("// And also _hidden=true");
    set_nodes_attributes(
        {R"({"tags" : {"_hidden": true, "_disconnect_existing_sessions_when_hidden": true} })",
         "", ""});

    SCOPED_TRACE("// The connection should get dropped");
    verify_existing_connection_dropped(rw_con_2.get());
  }

  // reset test (clear hidden flag)
  {
    SCOPED_TRACE(
        "// Unhide the node and et disconnect_existing_sessions_when_hidden to "
        "false");
    set_nodes_attributes(
        {R"({"tags" : {"_hidden": false, "_disconnect_existing_sessions_when_hidden": false })",
         "", ""});
  }

  // test tags: {hidden}
  {
    SCOPED_TRACE("// Make rw connection, should be ok");
    auto rw_con_3 = make_new_connection_ok(router_rw_port, node_ports[0]);

    SCOPED_TRACE("// Hide the node again");
    set_nodes_attributes(
        {R"({"tags" : {"_hidden": true, "_disconnect_existing_sessions_when_hidden": false })",
         "", ""});

    SCOPED_TRACE("// The existing connection should be ok");
    verify_existing_connection_ok(rw_con_3.get(), node_ports[0]);
  }
}

INSTANTIATE_TEST_SUITE_P(
    RWNodeHiddenDontDisconnectToggle, RWNodeHiddenDontDisconnectToggleTest,
    ::testing::Values(
        MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                              "rw_hidden_dont_disconnect_toggle_gr_v2",
                              ClusterType::GR_V2, "0.1"),
        MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                              "rw_hidden_dont_disconnect_toggle_ar_v2",
                              ClusterType::RS_V2, "0.1")),
    get_test_description);

class RWNodeHideThenDisconnectTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

/**
 * @test Verify _disconnect_existing_sessions_when_hidden also works when
 * applied AFTER hiding
 *
 * TS_FR04_02
 * */
TEST_P(RWNodeHideThenDisconnectTest, RWNodeHideThenDisconnect) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  setup_cluster(3, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);

  SCOPED_TRACE("// Make rw connection, should be ok");
  auto rw_con_1 = make_new_connection_ok(router_rw_port, node_ports[0]);

  SCOPED_TRACE("// Set disconnect_existing_sessions_when_hidden=false");
  set_nodes_attributes(
      {R"({"tags" : {"_disconnect_existing_sessions_when_hidden": false} })",
       "", ""});
  SCOPED_TRACE("// Then also set hidden=true");
  set_nodes_attributes(
      {R"({"tags" : {"_hidden": true, "_disconnect_existing_sessions_when_hidden": false} })",
       "", ""});

  SCOPED_TRACE("// The existing connection should stay ok");
  verify_existing_connection_ok(rw_con_1.get(), node_ports[0]);

  SCOPED_TRACE(
      "// Now disconnect_existing_sessions_when_hidden also gets set to true");
  set_nodes_attributes(
      {R"({"tags" : {"_hidden": true, "_disconnect_existing_sessions_when_hidden": true} })",
       "", ""});

  SCOPED_TRACE("// The existing connection should be disconnected");
  verify_existing_connection_dropped(rw_con_1.get());
}

INSTANTIATE_TEST_SUITE_P(
    RWNodeHideThenDisconnect, RWNodeHideThenDisconnectTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "rw_hide_then_disconnect_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "rw_hide_then_disconnect_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

/**
 * @test Verify _hidden works well with round-robin
 *
 * TS_FR02_05
 */
class RORoundRobinNodeHiddenTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(RORoundRobinNodeHiddenTest, RORoundRobinNodeHidden) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  setup_cluster(3, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);

  SCOPED_TRACE(
      "// Make one rw connection to check it's not affected by the RO being "
      "hidden");
  auto rw_con_1 = make_new_connection_ok(router_rw_port, node_ports[0]);

  SCOPED_TRACE("// Make ro connection, should be ok and go to the first RO");
  auto ro_con_1 = make_new_connection_ok(router_ro_port, node_ports[1]);

  SCOPED_TRACE("// Configure first RO node to be hidden");
  set_nodes_attributes({"", R"({"tags" : {"_hidden": true} })", ""});

  SCOPED_TRACE("// The existing connection should get dropped");
  verify_existing_connection_dropped(ro_con_1.get());

  SCOPED_TRACE(
      "// Make 2 new connections, both should go to the second RO node");
  auto ro_con_2 = make_new_connection_ok(router_ro_port, node_ports[2]);
  auto ro_con_3 = make_new_connection_ok(router_ro_port, node_ports[2]);

  SCOPED_TRACE("// Now hide also the second RO node");
  set_nodes_attributes({"", R"({"tags" : {"_hidden": true} })",
                        R"({"tags" : {"_hidden": true} })"});
  SCOPED_TRACE("// Both connections to that node should get dropped");
  verify_existing_connection_dropped(ro_con_2.get());
  verify_existing_connection_dropped(ro_con_3.get());
  SCOPED_TRACE(
      "// Since both RO nodes are hidden no new connection to RO port should "
      "be possible");
  verify_new_connection_fails(router_ro_port);

  SCOPED_TRACE("// Unhide the first RO node now");
  set_nodes_attributes({"", "", R"({"tags" : {"_hidden": true} })"});

  SCOPED_TRACE(
      "// Make 2 new connections, both should go to the first RO node this "
      "time");
  /*auto ro_con_4 =*/make_new_connection_ok(router_ro_port, node_ports[1]);
  /*auto ro_con_5 =*/make_new_connection_ok(router_ro_port, node_ports[1]);

  SCOPED_TRACE("// Unhide also the second RO node now");
  set_nodes_attributes({"", "", ""});

  SCOPED_TRACE(
      "// Make more connections to the RO port, they should be assinged in a "
      "round robin fashion as no node is hidden");
  /*auto ro_con_6 =*/make_new_connection_ok(router_ro_port, node_ports[1]);
  /*auto ro_con_7 =*/make_new_connection_ok(router_ro_port, node_ports[2]);
  /*auto ro_con_8 =*/make_new_connection_ok(router_ro_port, node_ports[1]);

  SCOPED_TRACE(
      "// RW connection that we made at the beginning should survive all of "
      "that");
  verify_existing_connection_ok(rw_con_1.get(), node_ports[0]);
}

INSTANTIATE_TEST_SUITE_P(
    RORoundRobinNodeHidden, RORoundRobinNodeHiddenTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "ro_round_robin_hidden_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "ro_round_robin_hidden_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class NodesHiddenWithFallbackTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(NodesHiddenWithFallbackTest, PrimaryHidden) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  setup_cluster(3, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type);
  std::string routing_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "round-robin", "", "rw");
  routing_section += get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin-with-fallback", "", "ro");

  launch_router(metadata_cache_section, routing_section, node_ports,
                EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Configure primary node to be hidden");
  set_nodes_attributes({R"({"tags" : {"_hidden": true} })", "", ""});
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Bring down secondary nodes, primary is hidden");
  ::set_mock_metadata(
      node_http_ports[0], "uuid", {GRNode(node_ports[0], "uuid-1")}, 0,
      {{node_ports[0], "uuid-1", 0, R"({"tags" : {"_hidden": true} })"}}, 0, 0,
      false, node_hostname);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  SCOPED_TRACE("// Bring up second secondary node, primary is hidden");
  ::set_mock_metadata(
      node_http_ports[0], "uuid",
      {GRNode(node_ports[0], "uuid-1"), GRNode(node_ports[2], "uuid-3")}, 0,
      {{node_ports[0], "uuid-1", 0, R"({"tags" : {"_hidden": true} })"},
       {node_ports[2], "uuid-3", 0, ""}},
      0, 0, false, node_hostname);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Unhide primary node");
  ::set_mock_metadata(
      node_http_ports[0], "uuid",
      {{node_ports[0], "uuid-1"}, {node_ports[2], "uuid-3"}}, 0,
      {{node_ports[0], "uuid-1", 0, ""}, {node_ports[2], "uuid-3", 0, ""}}, 0,
      0, false, node_hostname);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));
}

TEST_P(NodesHiddenWithFallbackTest, SecondaryHidden) {
  SCOPED_TRACE("// launch cluster with 3 nodes, 1 RW/2 RO");
  setup_cluster(3, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type);
  std::string routing_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "round-robin", "", "rw");
  routing_section += get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin-with-fallback", "", "ro");

  launch_router(metadata_cache_section, routing_section, node_ports,
                EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Configure second secondary node to be hidden");
  set_nodes_attributes({"", "", R"({"tags" : {"_hidden": true} })"});
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Bring down first primary node");
  ::set_mock_metadata(
      node_http_ports[0], "uuid",
      {{node_ports[0], "uuid-1"}, {node_ports[2], "uuid-3"}}, 0,
      {{node_ports[0], "uuid-1"},
       {node_ports[2], "uuid-3", 0, R"({"tags" : {"_hidden": true} })"}},
      0, 0, false, node_hostname);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Unhide second secondary node");
  ::set_mock_metadata(node_http_ports[0], "uuid",
                      {{node_ports[0], "uuid-1"}, {node_ports[2], "uuid-3"}}, 0,
                      {{node_ports[0], "uuid-1"}, {node_ports[2], "uuid-3"}}, 0,
                      0, false, node_hostname);
  EXPECT_TRUE(wait_for_transaction_count_increase(node_http_ports[0], 2));
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));
}

INSTANTIATE_TEST_SUITE_P(
    NodesHiddenWithFallback, NodesHiddenWithFallbackTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "hidden_with_fallback_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "hidden_with_fallback_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class OneNodeClusterHiddenTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {
 protected:
  void kill_server(ProcessWrapper *server) { EXPECT_NO_THROW(server->kill()); }
};

/**
 * @test Verify _hidden works fine with one node cluster and after the node
 * resurrection
 *
 * WL#13787: TS_FR02_06, TS_FR02_07
 * WL#13327: TS_R2_3
 */
TEST_P(OneNodeClusterHiddenTest, OneRWNodeClusterHidden) {
  SCOPED_TRACE("// launch one node cluster (single RW node)");
  setup_cluster(1, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);

  SCOPED_TRACE("// RW port should be used, RO is unused");
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  SCOPED_TRACE("// Hide the single node that we have");
  set_nodes_attributes({R"({"tags" : {"_hidden": true} })"});

  SCOPED_TRACE("// RW and RO ports are open");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  verify_new_connection_fails(router_rw_port);

  SCOPED_TRACE(
      "// Check that hiding also works after node dissapearing and getting "
      "back");
  kill_server(cluster_nodes[0]);

  SCOPED_TRACE(
      "// Relaunch the node, set the node as hidden from the very start");
  setup_cluster(1, GetParam().tracefile, {R"({"tags" : {"_hidden": true} })"});

  SCOPED_TRACE("// RW and RO ports are open");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  SCOPED_TRACE("// We still should not be able to connect");
  verify_new_connection_fails(router_rw_port);

  SCOPED_TRACE("// Un-hide the node");
  set_nodes_attributes({R"({"tags" : {"_hidden": false} })"});

  SCOPED_TRACE("// RW port should be used, RO is unused");
  EXPECT_TRUE(wait_for_port_used(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  SCOPED_TRACE("// Now we should be able to connect");
  make_new_connection_ok(router_rw_port, node_ports[0]);
}

/**
 * @test Test hiding a node in a single SECONDARY node cluster.
 *
 * WL#13327: TS_R2_4
 */
TEST_P(OneNodeClusterHiddenTest, OneRONodeClusterHidden) {
  SCOPED_TRACE("// launch one node cluster (single RO) node)");
  setup_cluster(1, GetParam().tracefile, {}, /*no_primary*/ true);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl, true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Hide the single node that we have");
  set_nodes_attributes({R"({"tags" : {"_hidden": true} })"},
                       /*no_primary*/ true);

  SCOPED_TRACE("// RW and RO ports are open");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  verify_new_connection_fails(router_rw_port);

  SCOPED_TRACE(
      "// Check that hiding also works after node dissapearing and getting "
      "back");
  kill_server(cluster_nodes[0]);

  SCOPED_TRACE(
      "// Relaunch the node, set the node as hidden from the very start");
  setup_cluster(1, GetParam().tracefile, {R"({"tags" : {"_hidden": true} })"},
                /*no_primary*/ true);

  SCOPED_TRACE("// RW and RO ports are open");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  SCOPED_TRACE("// We still should not be able to connect");
  verify_new_connection_fails(router_rw_port);

  SCOPED_TRACE("// Un-hide the node");
  set_nodes_attributes({R"({"tags" : {"_hidden": false} })"},
                       /*no_primary*/ true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Now we should be able to connect");
  make_new_connection_ok(router_ro_port, node_ports[0]);
}

INSTANTIATE_TEST_SUITE_P(
    OneNodeClusterHidden, OneNodeClusterHiddenTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "one_node_cluster_hidden_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "one_node_cluster_hidden_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class TwoNodesClusterHidden
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {
 protected:
  void kill_server(ProcessWrapper *server) { EXPECT_NO_THROW(server->kill()); }
};

/**
 * @test Test hiding a node in a two SECONDARY nodes cluster.
 *
 * WL#13327: TS_R2_5
 */
TEST_P(TwoNodesClusterHidden, TwoRONodesClusterHidden) {
  SCOPED_TRACE("// launch two nodes cluster (both SECONDARY) nodes)");
  setup_cluster(2, GetParam().tracefile, {}, /*no_primary*/ true);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl, true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Hide one node");
  set_nodes_attributes({R"({"tags" : {"_hidden": true} })", ""},
                       /*no_primary*/ true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Hide the second node as well");
  set_nodes_attributes(
      {R"({"tags" : {"_hidden": true} })", R"({"tags" : {"_hidden": true} })"},
      /*no_primary*/ true);

  SCOPED_TRACE("// RO and RW ports are unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_unused(router_ro_port));

  verify_new_connection_fails(router_rw_port);

  SCOPED_TRACE("// Un-hide one node");
  set_nodes_attributes({R"({"tags" : {"_hidden": false} })", ""},
                       /*no_primary*/ true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));

  SCOPED_TRACE("// Un-hide second node");
  set_nodes_attributes({"", ""}, /*no_primary*/ true);

  SCOPED_TRACE("// RO port should be used, RW is unused");
  EXPECT_TRUE(wait_for_port_unused(router_rw_port));
  EXPECT_TRUE(wait_for_port_used(router_ro_port));
}

INSTANTIATE_TEST_SUITE_P(
    TwoRONodesClusterHidden, TwoNodesClusterHidden,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "one_node_cluster_hidden_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "one_node_cluster_hidden_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class InvalidAttributesTagsTest
    : public NodeHiddenTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

/**
 * @test Checks that the router logs a proper warning once when the attributes
 * for the node becomes invalid.
 *
 * The test covers the following scenarios from the test plan (plus add some
 * more cases):
 * TS_log_parse_error_01 TS_log_parse_error_02
 */
TEST_P(InvalidAttributesTagsTest, InvalidAttributesTags) {
  SCOPED_TRACE("// launch cluster with 1 RW node");
  setup_cluster(1, GetParam().tracefile);

  SCOPED_TRACE("// launch the router with metadata-cache configuration");
  setup_router(GetParam().cluster_type, GetParam().ttl);

  SCOPED_TRACE("// Set the node's attributes to invalid JSON");
  set_nodes_attributes({"not a valid json for sure [] (}", ""});

  SCOPED_TRACE("// Check the expected warnings were logged once");
  check_log_contains(
      *router,
      "Error parsing _hidden from attributes JSON string: not a valid JSON "
      "object",
      1);
  check_log_contains(
      *router,
      "Error parsing _disconnect_existing_sessions_when_hidden from attributes "
      "JSON string: not a valid JSON object",
      1);

  SCOPED_TRACE("// Set the node's attributes.tags to invalid JSON");
  set_nodes_attributes({R"({"tags" : false})"});

  SCOPED_TRACE("// Check the expected warnings were logged once");
  check_log_contains(
      *router,
      "Error parsing _hidden from attributes JSON string: tags - not a valid "
      "JSON object",
      1);
  check_log_contains(
      *router,
      "Error parsing _disconnect_existing_sessions_when_hidden from attributes "
      "JSON string: tags - not a valid JSON object",
      1);

  SCOPED_TRACE("// Set the attributes.tags to be invalid types");
  set_nodes_attributes(
      {R"({"tags" : { "_hidden" : [], "_disconnect_existing_sessions_when_hidden": "True" }})"});

  SCOPED_TRACE("// Check the expected warnings were logged once");
  check_log_contains(
      *router,
      "Error parsing _hidden from attributes JSON string: tags._hidden not a "
      "boolean",
      1);
  check_log_contains(
      *router,
      "Error parsing _disconnect_existing_sessions_when_hidden from attributes "
      "JSON string: tags._disconnect_existing_sessions_when_hidden not a "
      "boolean",
      1);

  SCOPED_TRACE(
      "// Now fix both _hidden and _disconnect_existing_sessions_when_hidden "
      "in the metadata");
  set_nodes_attributes(
      {R"({"tags": { "_hidden" : false, "_disconnect_existing_sessions_when_hidden": false } })"});

  SCOPED_TRACE(
      "// Check the expected warnings about the attributes been valid were "
      "logged once");
  check_log_contains(
      *router, "Successfully parsed _hidden from attributes JSON string", 1);
  check_log_contains(
      *router,
      "Successfully parsed _disconnect_existing_sessions_when_hidden from "
      "attributes JSON string",
      1);

  SCOPED_TRACE("// Set the attributes.tags to be invalid types again");
  set_nodes_attributes(
      {R"({"tags" : { "_hidden" : [], "_disconnect_existing_sessions_when_hidden": "True" }})"});

  SCOPED_TRACE("// Check the expected warnings were logged twice");
  check_log_contains(
      *router,
      "Error parsing _hidden from attributes JSON string: tags._hidden not a "
      "boolean",
      2);
  check_log_contains(
      *router,
      "Error parsing _disconnect_existing_sessions_when_hidden from attributes "
      "JSON string: tags._disconnect_existing_sessions_when_hidden not a "
      "boolean",
      2);
}

INSTANTIATE_TEST_SUITE_P(
    InvalidAttributesTags, InvalidAttributesTagsTest,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "invalid_attributes_tags_gr_v2",
                                            ClusterType::GR_V2, "0.1"),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "invalid_attributes_tags_ar_v2",
                                            ClusterType::RS_V2, "0.1")),
    get_test_description);

class MetadataCacheMetadataServersOrder
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(MetadataCacheMetadataServersOrder, MetadataServersOrder) {
  const size_t kClusterNodes{3};
  std::vector<ProcessWrapper *> cluster_nodes;
  std::vector<uint16_t> md_servers_classic_ports, md_servers_http_ports;

  // launch the mock servers
  for (size_t i = 0; i < kClusterNodes; ++i) {
    const auto classic_port = port_pool_.get_next_available();
    const auto http_port = port_pool_.get_next_available();
    const std::string tracefile =
        get_data_dir().join(GetParam().tracefile).str();
    cluster_nodes.push_back(&launch_mysql_server_mock(
        tracefile, classic_port, EXIT_SUCCESS, false, http_port));

    md_servers_classic_ports.push_back(classic_port);
    md_servers_http_ports.push_back(http_port);
  }

  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_mock_metadata(http_port, "uuid",
                      classic_ports_to_gr_nodes(md_servers_classic_ports), i,
                      classic_ports_to_cluster_nodes(md_servers_classic_ports),
                      /*primary_id=*/0);
  }

  // launch the router with metadata-cache configuration
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, "0.1");
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const auto router_ro_port = port_pool_.get_next_available();
  const std::string routing_ro_section = get_metadata_cache_routing_section(
      router_ro_port, "PRIMARY", "round-robin", "", "ro");
  /*auto &router =*/
  launch_router(metadata_cache_section, routing_rw_section + routing_ro_section,
                md_servers_classic_ports, EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  // check first metadata server (PRIMARY) is queried for metadata
  EXPECT_TRUE(wait_for_transaction_count_increase(md_servers_http_ports[0], 2));

  // check that 2nd and 3rd servers (SECONDARIES) are NOT queried for metadata
  // in case of ReplicaSet Cluster every node gets queried for view_id so this
  // check would fail
  if (GetParam().cluster_type != mysqlrouter::ClusterType::RS_V2) {
    for (const auto i : {1, 2}) {
      EXPECT_FALSE(wait_for_transaction_count_increase(md_servers_http_ports[i],
                                                       1, 200ms));
    }
  }

  // check that the PRIMARY is first in the state file
  check_state_file(state_file_, GetParam().cluster_type, "uuid",
                   {md_servers_classic_ports[0], md_servers_classic_ports[1],
                    md_servers_classic_ports[2]});

  // now promote first SECONDARY to become new PRIMARY
  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_mock_metadata(http_port, "uuid",
                      classic_ports_to_gr_nodes(md_servers_classic_ports), i,
                      classic_ports_to_cluster_nodes(md_servers_classic_ports),
                      /*primary_id=*/1);
  }

  // check that the second metadata server (new PRIMARY) is queried for metadata
  EXPECT_TRUE(wait_for_transaction_count_increase(md_servers_http_ports[1], 2));

  // check that 1st and 3rd servers (new SECONDARIES) are NOT queried for
  // metadata in case of ReplicaSet Cluster every node gets queried for view_id
  // so this check would fail
  if (GetParam().cluster_type != mysqlrouter::ClusterType::RS_V2) {
    for (const auto i : {0, 2}) {
      EXPECT_FALSE(wait_for_transaction_count_increase(
          md_servers_http_ports[i], 1, std::chrono::milliseconds(500)));
    }
  }

  // check that the new PRIMARY is first in the state file
  check_state_file(state_file_, GetParam().cluster_type, "uuid",
                   {md_servers_classic_ports[1], md_servers_classic_ports[0],
                    md_servers_classic_ports[2]});
}

INSTANTIATE_TEST_SUITE_P(
    MetadataServersOrder, MetadataCacheMetadataServersOrder,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "GR_V2", ClusterType::GR_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "AR", ClusterType::RS_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes.js",
                                            "GR_V1", ClusterType::GR_V1)),
    get_test_description);

class MetadataServerInvalidGRState
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(MetadataServerInvalidGRState, InvalidGRState) {
  const size_t kClusterNodes{3};
  std::vector<ProcessWrapper *> cluster_nodes;
  std::vector<uint16_t> md_servers_classic_ports, md_servers_http_ports;

  // launch the server mocks
  for (size_t i = 0; i < kClusterNodes; ++i) {
    const auto classic_port = port_pool_.get_next_available();
    const auto http_port = port_pool_.get_next_available();
    const std::string tracefile =
        get_data_dir().join(GetParam().tracefile).str();
    cluster_nodes.push_back(&launch_mysql_server_mock(
        tracefile, classic_port, EXIT_SUCCESS, false, http_port));

    md_servers_classic_ports.push_back(classic_port);
    md_servers_http_ports.push_back(http_port);
  }

  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_mock_metadata(http_port, "uuid",
                      classic_ports_to_gr_nodes(md_servers_classic_ports), i,
                      classic_ports_to_cluster_nodes(md_servers_classic_ports),
                      /*primary_id=*/0);
  }

  // launch the router with metadata-cache configuration
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, "0.1");
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const auto router_ro_port = port_pool_.get_next_available();
  const std::string routing_ro_section = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin", "", "ro");
  auto &router = launch_router(metadata_cache_section,
                               routing_rw_section + routing_ro_section,
                               md_servers_classic_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // check first metadata server (PRIMARY) is queried for metadata
  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[0], 2, 5s));

  // check that 2nd and 3rd servers (SECONDARIES) are NOT queried for metadata
  for (const auto i : {1, 2}) {
    EXPECT_FALSE(wait_for_transaction_count_increase(md_servers_http_ports[i],
                                                     1, 200ms));
  }

  // now promote first SECONDARY to become new PRIMARY
  // make the old PRIMARY offline (static metadata does not change)
  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    if (i == 0) {
      // old PRIMARY sees itself as OFFLINE, does not see other nodes
      const auto gr_nodes = std::vector<GRNode>{
          {md_servers_classic_ports[0], "uuid-1", "OFFLINE"}};
      ::set_mock_metadata(
          http_port, "uuid", gr_nodes, 0,
          classic_ports_to_cluster_nodes(md_servers_classic_ports),
          /*primary_id=*/0);
    } else {
      // remaining nodes see the previous SECONDARY-1 as new primary
      // they do not see old PRIMARY (it was expelled from the group)
      const auto gr_nodes = std::vector<GRNode>{
          {{md_servers_classic_ports[1], "uuid-2", "ONLINE"},
           {md_servers_classic_ports[2], "uuid-3", "ONLINE"}}};
      ::set_mock_metadata(
          http_port, "uuid", gr_nodes, i - 1,
          classic_ports_to_cluster_nodes(md_servers_classic_ports),
          /*primary_id=*/0);
    }
  }

  // check that the second metadata server (new PRIMARY) is queried for metadata
  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[1], 2, 5s));

  // check that Router refused to use metadata from former PRIMARY (only once,
  // then should stop using it)
  check_log_contains(router,
                     "Metadata server 127.0.0.1:" +
                         std::to_string(md_servers_classic_ports[0]) +
                         " is not an online GR member - skipping.",
                     1);

  // new connections are now handled by new primary and the secon secondary
  make_new_connection_ok(router_rw_port, md_servers_classic_ports[1]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[2]);
}

INSTANTIATE_TEST_SUITE_P(
    InvalidGRState, MetadataServerInvalidGRState,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "GR_V2", ClusterType::GR_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes.js",
                                            "GR_V1", ClusterType::GR_V1)),
    get_test_description);

class MetadataServerNoQuorum
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(MetadataServerNoQuorum, NoQuorum) {
  const size_t kClusterNodes{3};
  std::vector<ProcessWrapper *> cluster_nodes;
  std::vector<uint16_t> md_servers_classic_ports, md_servers_http_ports;

  // launch the server mocks
  for (size_t i = 0; i < kClusterNodes; ++i) {
    const auto classic_port = port_pool_.get_next_available();
    const auto http_port = port_pool_.get_next_available();
    const std::string tracefile =
        get_data_dir().join(GetParam().tracefile).str();
    cluster_nodes.push_back(&launch_mysql_server_mock(
        tracefile, classic_port, EXIT_SUCCESS, false, http_port));

    md_servers_classic_ports.push_back(classic_port);
    md_servers_http_ports.push_back(http_port);
  }

  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_mock_metadata(http_port, "uuid",
                      classic_ports_to_gr_nodes(md_servers_classic_ports), i,
                      classic_ports_to_cluster_nodes(md_servers_classic_ports),
                      /*primary_id=*/0);
  }

  // launch the router with metadata-cache configuration
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type, "0.1");
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const auto router_ro_port = port_pool_.get_next_available();
  const std::string routing_ro_section = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin", "", "ro");
  auto &router = launch_router(metadata_cache_section,
                               routing_rw_section + routing_ro_section,
                               md_servers_classic_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // check first metadata server (PRIMARY) is queried for metadata
  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[0], 2, 5s));

  // check that 2nd and 3rd servers (SECONDARIES) are NOT queried for metadata
  for (const auto i : {1, 2}) {
    EXPECT_FALSE(wait_for_transaction_count_increase(md_servers_http_ports[i],
                                                     1, 200ms));
  }

  // now promote first SECONDARY to become new PRIMARY
  // make the old PRIMARY see other as OFFLINE and claim it is ONLINE
  // (static metadata does not change)
  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    if (i == 0) {
      // old PRIMARY still sees itself as ONLINE, but it lost quorum, do not
      // see other GR members
      const auto gr_nodes = std::vector<GRNode>{
          {md_servers_classic_ports[0], "uuid-1", "ONLINE"},
          {md_servers_classic_ports[1], "uuid-2", "OFFLINE"},
          {md_servers_classic_ports[2], "uuid-3", "OFFLINE"}};
      ::set_mock_metadata(
          http_port, "uuid", gr_nodes, 0,
          classic_ports_to_cluster_nodes(md_servers_classic_ports),
          /*primary_id=*/0);
    } else {
      // remaining nodes see the previous SECONDARY-1 as new primary
      // they do not see old PRIMARY (it was expelled from the group)
      const auto gr_nodes = std::vector<GRNode>{
          {{md_servers_classic_ports[1], "uuid-2", "ONLINE"},
           {md_servers_classic_ports[2], "uuid-3", "ONLINE"}}};
      ::set_mock_metadata(
          http_port, "uuid", gr_nodes, i - 1,
          classic_ports_to_cluster_nodes(md_servers_classic_ports),
          /*primary_id=*/0);
    }
  }

  // check that the second metadata server (new PRIMARY) is queried for metadata
  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[1], 2, 5s));

  // check that Router refused to use metadata from former PRIMARY (only once,
  // then should stop using it)
  check_log_contains(router,
                     "Metadata server 127.0.0.1:" +
                         std::to_string(md_servers_classic_ports[0]) +
                         " is not a member of quorum group - skipping.",
                     1);

  // new connections are now handled by new primary and the secon secondary
  make_new_connection_ok(router_rw_port, md_servers_classic_ports[1]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[2]);
}

INSTANTIATE_TEST_SUITE_P(
    NoQuorum, MetadataServerNoQuorum,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "GR_V2", ClusterType::GR_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes.js",
                                            "GR_V1", ClusterType::GR_V1)),
    get_test_description);

class MetadataServerGRErrorStates
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<std::string> {};

/**
 * @test Checks that the Router correctly handles non-ONLINE GR nodes
 */
TEST_P(MetadataServerGRErrorStates, GRErrorStates) {
  const std::string tracefile =
      get_data_dir().join("metadata_dynamic_nodes_v2_gr.js").str();

  // launch the server mock
  const auto md_servers_classic_port = port_pool_.get_next_available();
  const auto md_servers_http_port = port_pool_.get_next_available();
  launch_mysql_server_mock(tracefile, md_servers_classic_port, EXIT_SUCCESS,
                           false, md_servers_http_port);

  std::vector<GRNode> gr_nodes{{md_servers_classic_port, "uuid-1", GetParam()}};
  ::set_mock_metadata(md_servers_http_port, "uuid", gr_nodes, 0,
                      classic_ports_to_cluster_nodes({md_servers_classic_port}),
                      /*primary_id=*/0);

  // launch the router with metadata-cache configuration
  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V2, "0.1");
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  auto &router = launch_router(metadata_cache_section, routing_rw_section,
                               {md_servers_classic_port}, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/-1s);

  EXPECT_TRUE(wait_for_transaction_count_increase(md_servers_http_port, 2, 5s));

  const std::string expected_string =
      "Metadata server 127.0.0.1:" + std::to_string(md_servers_classic_port) +
      " is not an online GR member - skipping.";

  const std::string log_content = router.get_logfile_content();
  EXPECT_GE(count_str_occurences(log_content, expected_string), 1)
      << log_content;
}

INSTANTIATE_TEST_SUITE_P(GRErrorStates, MetadataServerGRErrorStates,
                         ::testing::Values("OFFLINE", "UNREACHABLE",
                                           "RECOVERING", "ERROR", "UNKNOWN", "",
                                           ".."));

class MetadataCacheChangeClusterName
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<MetadataTTLTestParams> {};

TEST_P(MetadataCacheChangeClusterName, ChangeClusterName) {
  const size_t kClusterNodes{2};
  std::vector<ProcessWrapper *> cluster_nodes;
  std::vector<uint16_t> md_servers_classic_ports, md_servers_http_ports;

  const std::string kInitialClusterName = "initial_cluster_name";
  const std::string kChangedClusterName = "changed_cluster_name";

  // launch the mock servers
  for (size_t i = 0; i < kClusterNodes; ++i) {
    const auto classic_port = port_pool_.get_next_available();
    const auto http_port = port_pool_.get_next_available();
    const std::string tracefile =
        get_data_dir().join(GetParam().tracefile).str();
    cluster_nodes.push_back(&launch_mysql_server_mock(
        tracefile, classic_port, EXIT_SUCCESS, false, http_port));

    md_servers_classic_ports.push_back(classic_port);
    md_servers_http_ports.push_back(http_port);
  }

  auto set_metadata = [&](uint16_t http_port, unsigned int gr_pos,
                          const std::string &cluster_name) {
    auto globals = mock_GR_metadata_as_json(
        "uuid", classic_ports_to_gr_nodes(md_servers_classic_ports), gr_pos,
        classic_ports_to_cluster_nodes(md_servers_classic_ports));
    JsonAllocator allocator;
    globals.AddMember(
        "cluster_name",
        JsonValue(cluster_name.c_str(), cluster_name.length(), allocator),
        allocator);
    const auto globals_str = json_to_string(globals);
    MockServerRestClient(http_port).set_globals(globals_str);
  };

  // initially set the name of the cluster in the metadata to the same value
  // that was set in the Router configuration file
  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_metadata(http_port, i, kInitialClusterName);
  }

  // launch the router
  const std::string metadata_cache_section = get_metadata_cache_section(
      GetParam().cluster_type, "0.1", kInitialClusterName);
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const auto router_ro_port = port_pool_.get_next_available();
  const std::string routing_ro_section = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin", "", "ro");
  auto &router = launch_router(metadata_cache_section,
                               routing_rw_section + routing_ro_section,
                               md_servers_classic_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // make sure that Router works
  make_new_connection_ok(router_rw_port, md_servers_classic_ports[0]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[1]);

  // now change the cluster name in the metadata
  for (const auto [i, http_port] :
       stdx::views::enumerate(md_servers_http_ports)) {
    set_metadata(http_port, i, kChangedClusterName);
  }

  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[0], 2, 5s));

  // the Router should still work
  make_new_connection_ok(router_rw_port, md_servers_classic_ports[0]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[1]);

  // now stop the Router and start it again, this is to make sure that not only
  // change of the ClusterName while the Router is running works but also when
  // it is restarted and loads the configuration from scratch
  EXPECT_NO_THROW(router.kill());
  check_exit_code(router, EXIT_SUCCESS, 5s);

  /*auto &router2 = */ launch_router(metadata_cache_section,
                                     routing_rw_section + routing_ro_section,
                                     md_servers_classic_ports, EXIT_SUCCESS,
                                     /*wait_for_notify_ready=*/30s);

  make_new_connection_ok(router_rw_port, md_servers_classic_ports[0]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[1]);
}

INSTANTIATE_TEST_SUITE_P(
    ChangeClusterName, MetadataCacheChangeClusterName,
    ::testing::Values(MetadataTTLTestParams("metadata_dynamic_nodes_v2_gr.js",
                                            "GR_V2", ClusterType::GR_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes_v2_ar.js",
                                            "AR", ClusterType::RS_V2),
                      MetadataTTLTestParams("metadata_dynamic_nodes.js",
                                            "GR_V1", ClusterType::GR_V1)),
    get_test_description);

struct SessionReuseTestParams {
  std::string router_ssl_mode;
  bool server_ssl_enabled;
  bool expected_session_reuse;
};

class SessionReuseTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<SessionReuseTestParams> {};

/**
 * @test Checks that the SSL sessions to the server, that metadata cache is
 * creating to refresh metadata, are reused if SSL is used
 */
TEST_P(SessionReuseTest, SessionReuse) {
  std::vector<uint16_t> classic_ports, http_ports;
  std::vector<ProcessWrapper *> cluster_nodes;
  const auto test_params = GetParam();

  const size_t kClusterNodes = 2;
  for (size_t i = 0; i < kClusterNodes; ++i) {
    classic_ports.push_back(port_pool_.get_next_available());
    http_ports.push_back(port_pool_.get_next_available());
  }
  const std::string json_metadata =
      get_data_dir().join("metadata_dynamic_nodes_v2_gr.js").str();

  for (size_t i = 0; i < kClusterNodes; ++i) {
    cluster_nodes.push_back(&launch_mysql_server_mock(
        json_metadata, classic_ports[i], EXIT_SUCCESS, false, http_ports[i], 0,
        "", "0.0.0.0", 30s, /*enable_ssl*/ test_params.server_ssl_enabled));
    set_mock_metadata(http_ports[i], "uuid",
                      classic_ports_to_gr_nodes(classic_ports), 0,
                      classic_ports_to_cluster_nodes(classic_ports));
  }

  const auto router_rw_port = port_pool_.get_next_available();
  const std::string metadata_cache_section = get_metadata_cache_section(
      ClusterType::GR_V2, "0.2", "test", test_params.router_ssl_mode);
  const std::string routing_rw = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");

  launch_router(metadata_cache_section, routing_rw, classic_ports, EXIT_SUCCESS,
                /*wait_for_notify_ready=*/30s);

  // wait for several metadata cache refresh cycles
  EXPECT_TRUE(wait_for_transaction_count_increase(http_ports[0], 4));

  MySQLSession client;
  ASSERT_NO_FATAL_FAILURE(client.connect("127.0.0.1", classic_ports[0],
                                         "username", "password", "", ""));

  // check how many sessions were reused on the metadata server side
  std::unique_ptr<mysqlrouter::MySQLSession::ResultRow> result{
      client.query_one("SHOW STATUS LIKE 'Ssl_session_cache_hits'")};
  ASSERT_NE(nullptr, result.get());
  ASSERT_EQ(1u, result->size());
  const auto cache_hits = std::atoi((*result)[0]);
  if (test_params.expected_session_reuse) {
    EXPECT_GT(cache_hits, 0);
  } else {
    EXPECT_EQ(0, cache_hits);
  }
}

INSTANTIATE_TEST_SUITE_P(
    SessionReuse, SessionReuseTest,

    ::testing::Values(
        /* default ssl_mode in the Router ("PREFERRED"), ssl enabled on the
           server side so we expect session reuse */
        SessionReuseTestParams{
            /*router_ssl_mode*/ "",
            /*server_ssl_enabled*/ true,
            /*expected_session_reuse*/ true,
        },

        /* ssl_mode in the Router "REQUIRED", ssl enabled on the server side so
           we expect session reuse */
        SessionReuseTestParams{/*router_ssl_mode*/ "REQUIRED",
                               /*server_ssl_enabled*/ true,
                               /*expected_session_reuse*/ true},

        /* ssl_mode in the Router "PREFERRED", ssl disabled on the server side
         so we DON'T expect session reuse */
        SessionReuseTestParams{/*router_ssl_mode*/ "PREFERRED",
                               /*server_ssl_enabled*/ false,
                               /*expected_session_reuse*/ false},

        /* ssl_mode in the Router "DISABLED", ssl enabled on the server side
           so we DON'T expect session reuse */
        SessionReuseTestParams{/*router_ssl_mode*/ "DISABLED",
                               /*server_ssl_enabled*/ true,
                               /*expected_session_reuse*/ false}));

struct QuorumTestParam {
  std::string test_name;

  std::vector<GRNode> gr_nodes;
  std::vector<ClusterNode> cluster_nodes;

  std::vector<uint16_t> expected_rw_endpoints;
  std::vector<uint16_t> expected_ro_endpoints;
};

class QuorumTest : public MetadataChacheTTLTest,
                   public ::testing::WithParamInterface<QuorumTestParam> {
 public:
  void SetUp() override {
    MetadataChacheTTLTest::SetUp();
    for (size_t i = 0; i < 3; ++i) {
      classic_ports.push_back(port_pool_.get_next_available());
      http_ports.push_back(port_pool_.get_next_available());
    }
  }

 protected:
  std::vector<uint16_t> classic_ports, http_ports;
};

/**
 * @test Testing various quorum scenarios.
 */
TEST_P(QuorumTest, Verify) {
  const std::string json_metadata =
      get_data_dir().join("metadata_dynamic_nodes_v2_gr.js").str();

  auto param = GetParam();
  std::vector<uint16_t> cluster_classic_ports;
  // The ports set via INSTANTIATE_TEST_SUITE_P are only ids
  // (INSTANTIATE_TEST_SUITE_P does not have access to classic_ports vector). We
  // need to fill them up here.
  const auto primary_http_port =
      http_ports[param.cluster_nodes[0].classic_port];
  for (auto &node : param.gr_nodes) {
    node.classic_port = classic_ports[node.classic_port];
  }
  for (auto &node : param.cluster_nodes) {
    node.classic_port = classic_ports[node.classic_port];
    cluster_classic_ports.push_back(node.classic_port);
  }
  for (auto &port : param.expected_rw_endpoints) {
    port = classic_ports[port];
  }
  for (auto &port : param.expected_ro_endpoints) {
    port = classic_ports[port];
  }

  const bool expect_rw_ok = !param.expected_rw_endpoints.empty();
  const bool expect_ro_ok = !param.expected_rw_endpoints.empty();

  for (const auto [id, port] : stdx::views::enumerate(classic_ports)) {
    launch_mysql_server_mock(json_metadata, port, EXIT_SUCCESS, false,
                             http_ports[id]);
    ::set_mock_metadata(http_ports[id], "uuid", param.gr_nodes, 0,
                        param.cluster_nodes);
  }

  const auto router_ro_port = port_pool_.get_next_available();
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string metadata_cache_section =
      get_metadata_cache_section(ClusterType::GR_V2, "0.2");
  const std::string routing_rw = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const std::string routing_ro = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin-with-fallback", "", "ro");

  /*auto &router = */ launch_router(metadata_cache_section,
                                    routing_rw + routing_ro,
                                    cluster_classic_ports, EXIT_SUCCESS,
                                    /*wait_for_notify_ready=*/-1s);

  EXPECT_TRUE(wait_for_transaction_count_increase(primary_http_port, 2));

  for (int i = 0; i < 2; i++) {
    if (expect_rw_ok) {
      make_new_connection_ok(router_rw_port, param.expected_rw_endpoints);
    } else {
      verify_new_connection_fails(router_rw_port);
    }

    if (expect_ro_ok) {
      make_new_connection_ok(router_ro_port, param.expected_ro_endpoints);
    } else {
      verify_new_connection_fails(router_ro_port);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    Spec, QuorumTest,
    ::testing::Values(
        // 2 nodes: 1 ONLINE, 1 OFFLINE = no quorum, no connections handled
        QuorumTestParam{
            "1_online_1_offline",
            /*gr_nodes*/
            {{0, "uuid-1", "ONLINE"}, {1, "uuid-2", "OFFLINE"}},
            /*cluster_nodes*/
            {{0, "uuid-1"}, {1, "uuid-2"}},
            /*expected_rw_endpoints*/
            {},
            /*expected_ro_endpoints*/
            {},
        },
        // 2 nodes: 1 ONLINE, 1 RECOVERING = quorum, connections handled
        QuorumTestParam{
            "1_online_1_recovering",
            /*gr_nodes*/
            {{0, "uuid-1", "ONLINE"}, {1, "uuid-2", "RECOVERING"}},
            /*cluster_nodes*/
            {{0, "uuid-1"}, {1, "uuid-2"}},
            /*expected_rw_endpoints*/
            {0},
            /*expected_ro_endpoints*/
            {0},
        },
        // 3 nodes: 1 ONLINE, 2 RECOVERING = quorum, connections handled
        QuorumTestParam{
            "1_online_2_recovering",
            /*gr_nodes*/
            {{0, "uuid-1", "ONLINE"},
             {1, "uuid-2", "RECOVERING"},
             {2, "uuid-3", "RECOVERING"}},
            /*cluster_nodes*/
            {{0, "uuid-1"}, {1, "uuid-2"}, {2, "uuid-3"}},
            /*expected_rw_endpoints*/
            {0},
            /*expected_ro_endpoints*/
            {0},
        },
        // There are 2 nodes in GR, only one of them is defined in the metadata.
        // The RW and RO connections should still be possible and should be only
        // reaching the node that is present in both GR and cluster metadata.
        QuorumTestParam{
            "2_online_1_missing_in_metadata",
            /*gr_nodes*/
            {{0, "uuid-1", "ONLINE"}, {1, "uuid-2", "ONLINE"}},
            /*cluster_nodes*/
            {{0, "uuid-1"}},
            /*expected_rw_endpoints*/
            {0},
            /*expected_ro_endpoints*/
            {0},
        },
        // There are 2 nodes in GR, one node in the cluster metadata.
        // The one in the cluster metadata is not present in the GR, no
        // connections should be possible.
        QuorumTestParam{
            "2_online_both_missing_in_metadata",
            /*gr_nodes*/
            {{0, "uuid-1", "ONLINE"}, {1, "uuid-2", "ONLINE"}},
            /*cluster_nodes*/
            {{2, "uuid-3"}},
            /*expected_rw_endpoints*/
            {},
            /*expected_ro_endpoints*/
            {},
        }),
    [](const ::testing::TestParamInfo<QuorumTestParam> &info) {
      return info.param.test_name;
    });

static constexpr const unsigned long max_supported_version =
    MYSQL_ROUTER_VERSION_MAJOR * 10000 + MYSQL_ROUTER_VERSION_MINOR * 100 + 99;

struct ServerCompatTestParam {
  std::string description;
  ClusterType cluster_type;
  std::string tracefile;
  std::string server_version;
  bool expect_failure;
  std::string expected_error_msg;
};

class CheckServerCompatibilityTest
    : public MetadataChacheTTLTest,
      public ::testing::WithParamInterface<ServerCompatTestParam> {};

/**
 * @test
 *       Verifies that the server version is checked for compatibility when the
 * Router is running with the GR Cluster and Replica Set
 */
TEST_P(CheckServerCompatibilityTest, Spec) {
  RecordProperty("Description", GetParam().description);

  const size_t kClusterNodes{2};
  std::vector<ProcessWrapper *> cluster_nodes;
  std::vector<uint16_t> md_servers_classic_ports, md_servers_http_ports;

  const std::string tracefile = get_data_dir().join(GetParam().tracefile).str();
  // launch the mock servers
  for (size_t i = 0; i < kClusterNodes; ++i) {
    const auto classic_port = port_pool_.get_next_available();
    const auto http_port = port_pool_.get_next_available();
    cluster_nodes.push_back(&launch_mysql_server_mock(
        tracefile, classic_port, EXIT_SUCCESS, false, http_port));

    md_servers_classic_ports.push_back(classic_port);
    md_servers_http_ports.push_back(http_port);
  }

  for (const auto http_port : md_servers_http_ports) {
    set_mock_metadata(http_port, "uuid",
                      classic_ports_to_gr_nodes(md_servers_classic_ports), 0,
                      classic_ports_to_cluster_nodes(md_servers_classic_ports));
  }

  // launch the router
  const std::string metadata_cache_section =
      get_metadata_cache_section(GetParam().cluster_type);
  const auto router_rw_port = port_pool_.get_next_available();
  const std::string routing_rw_section = get_metadata_cache_routing_section(
      router_rw_port, "PRIMARY", "first-available", "", "rw");
  const auto router_ro_port = port_pool_.get_next_available();
  const std::string routing_ro_section = get_metadata_cache_routing_section(
      router_ro_port, "SECONDARY", "round-robin", "", "ro");
  auto &router = launch_router(metadata_cache_section,
                               routing_rw_section + routing_ro_section,
                               md_servers_classic_ports, EXIT_SUCCESS,
                               /*wait_for_notify_ready=*/30s);

  // make sure that Router works
  make_new_connection_ok(router_rw_port, md_servers_classic_ports[0]);
  make_new_connection_ok(router_ro_port, md_servers_classic_ports[1]);

  // change the cluster nodes versions
  for (const auto http_port : md_servers_http_ports) {
    set_mock_server_version(http_port, GetParam().server_version);
  }

  EXPECT_TRUE(
      wait_for_transaction_count_increase(md_servers_http_ports[0], 5, 5s));

  if (GetParam().expect_failure) {
    verify_new_connection_fails(router_rw_port);
    verify_new_connection_fails(router_ro_port);

    EXPECT_TRUE(wait_log_contains(router, GetParam().expected_error_msg, 5s));
  } else {
    make_new_connection_ok(router_rw_port, md_servers_classic_ports[0]);
    make_new_connection_ok(router_ro_port, md_servers_classic_ports[1]);
  }
}

INSTANTIATE_TEST_SUITE_P(
    Spec, CheckServerCompatibilityTest,
    ::testing::Values(
        ServerCompatTestParam{
            "GR Cluster; Server is the same version as Router - OK",
            ClusterType::GR_V2, "metadata_dynamic_nodes_v2_gr.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH),
            false, ""},
        ServerCompatTestParam{
            "Replica Set; Server is the same version as Router - OK",
            ClusterType::RS_V2, "metadata_dynamic_nodes_v2_ar.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH),
            false, ""},
        ServerCompatTestParam{
            "GR Cluster; Server major version is highier than Router - "
            "we should reject the metadata",
            ClusterType::GR_V2, "metadata_dynamic_nodes_v2_gr.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR + 1) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH),
            true,
            "WARNING .* Unsupported MySQL Server version '.*'. Maximal "
            "supported version is '" +
                std::to_string(max_supported_version) + "'."},
        ServerCompatTestParam{
            "GR Cluster; Server minor version is highier than Router - "
            "we should reject the metadata",
            ClusterType::GR_V2, "metadata_dynamic_nodes_v2_gr.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR + 1) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH),
            true,
            "WARNING .* Unsupported MySQL Server version '.*'. Maximal "
            "supported version is '" +
                std::to_string(max_supported_version) + "'."},
        ServerCompatTestParam{
            "GR Cluster; Server patch version is highier than Router - OK",
            ClusterType::GR_V2, "metadata_dynamic_nodes_v2_gr.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH + 1),
            false, ""},
        ServerCompatTestParam{
            "Replica Set; Server minor version is highier than Router - "
            "we should reject the metadata",
            ClusterType::RS_V2, "metadata_dynamic_nodes_v2_ar.js",
            std::to_string(MYSQL_ROUTER_VERSION_MAJOR) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_MINOR + 1) + "." +
                std::to_string(MYSQL_ROUTER_VERSION_PATCH),
            true,
            "WARNING .* Unsupported MySQL Server version '.*'. Maximal "
            "supported version is '" +
                std::to_string(max_supported_version) + "'."}));

int main(int argc, char *argv[]) {
  init_windows_sockets();
  ProcessManager::set_origin(Path(argv[0]).dirname());
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
