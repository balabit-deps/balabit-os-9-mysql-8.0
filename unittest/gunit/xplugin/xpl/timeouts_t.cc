/* Copyright (c) 2017, 2025, Oracle and/or its affiliates.

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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "plugin/x/src/client.h"
#include "plugin/x/src/ngs/protocol_encoder.h"
#include "plugin/x/src/operations_factory.h"
#include "plugin/x/src/variables/system_variables.h"
#include "plugin/x/src/variables/system_variables_defaults.h"
#include "plugin/x/src/variables/timeout_config.h"
#include "unittest/gunit/xplugin/xpl/mock/notice_output_queue.h"
#include "unittest/gunit/xplugin/xpl/mock/protocol_encoder.h"
#include "unittest/gunit/xplugin/xpl/mock/protocol_monitor.h"
#include "unittest/gunit/xplugin/xpl/mock/server.h"
#include "unittest/gunit/xplugin/xpl/mock/session.h"
#include "unittest/gunit/xplugin/xpl/mock/vio.h"
#include "unittest/gunit/xplugin/xpl/mock/waiting_for_io.h"

namespace xpl {
namespace test {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Expectation;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::ReturnPointee;
using ::testing::ReturnRef;
using ::testing::SetArrayArgument;
using ::testing::StrictMock;

class Timers_test_suite : public ::testing::Test {
 public:
  void SetUp() override {
    config->m_timeouts.m_interactive_timeout =
        defaults::timeout::k_interactive_timeout;
    config->m_timeouts.m_read_timeout = defaults::timeout::k_read_timeout;
    config->m_timeouts.m_write_timeout = defaults::timeout::k_write_timeout;

    EXPECT_CALL(mock_server, get_config()).WillRepeatedly(Return(config));
    EXPECT_CALL(mock_server, is_running()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_vio, get_mysql_socket())
        .WillRepeatedly(ReturnRef(m_socket));
    EXPECT_CALL(*mock_wait_for_io, has_to_report_idle_waiting())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*mock_wait_for_io, on_idle_or_before_read())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_session, get_notice_output_queue())
        .WillRepeatedly(ReturnRef(mock_notice_output_queue));
    EXPECT_CALL(*mock_protocol_monitor, init(_));

    sut = std::make_shared<Client>(mock_vio, &mock_server, /* id */ 1,
                                   mock_protocol_monitor);
    sut->set_session(mock_session);
    sut->set_idle_reporting(mock_wait_for_io);
  }

  void TearDown() override { EXPECT_CALL(*mock_vio, shutdown()); }

  using Strict_mock_vio = StrictMock<mock::Vio>;
  std::shared_ptr<Strict_mock_vio> mock_vio{new Strict_mock_vio()};
  StrictMock<mock::Server> mock_server;
  StrictMock<mock::Protocol_monitor> *mock_protocol_monitor =
      ngs::allocate_object<StrictMock<mock::Protocol_monitor>>();
  StrictMock<mock::Notice_output_queue> mock_notice_output_queue;
  StrictMock<mock::Waiting_for_io> *mock_wait_for_io{
      new StrictMock<mock::Waiting_for_io>};

  std::shared_ptr<ngs::Protocol_global_config> config{
      new ngs::Protocol_global_config()};
  ngs::Memory_block_pool m_pool{{0, k_minimum_page_size}};
  const std::vector<unsigned char> k_msg{
      1, 0, 0, 0, 1};  // 1 = size, 0, 0, 0, 1 = Msg_CapGet

  StrictMock<mock::Session> *mock_session = new StrictMock<mock::Session>();
  std::shared_ptr<Client> sut;
  MYSQL_SOCKET m_socket{INVALID_SOCKET, nullptr};
};

ACTION_P2(SetSocketErrnoAndReturn, err, result) {
  xpl::Operations_factory operations_factory;

  operations_factory.create_system_interface()->set_socket_errno(err);

  return result;
}

TEST_F(Timers_test_suite,
       read_one_message_non_interactive_client_default_wait_timeout) {
  // Client holds only the timeout value which must be used.
  // It doesn't hold interactive or non-interactive timeout values.
  // The timeout value is set from outside thus the test uses
  // k_interactive_timeout
  Expectation set_timeout_exp = EXPECT_CALL(
      *mock_vio,
      set_timeout_in_ms(iface::Vio::Direction::k_read,
                        defaults::timeout::k_interactive_timeout * 1000));

  EXPECT_CALL(*mock_vio, read(_, _))
      .After(set_timeout_exp)
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end()),
                      Return(k_msg.size())));

  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size()));
  EXPECT_CALL(*mock_session, handle_message(_));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite,
       read_one_message_interactive_client_default_interactive_timeout) {
  Expectation set_timeout_exp = EXPECT_CALL(
      *mock_vio,
      set_timeout_in_ms(iface::Vio::Direction::k_read,
                        defaults::timeout::k_interactive_timeout * 1000));

  EXPECT_CALL(*mock_vio, read(_, _))
      .After(set_timeout_exp)
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end()),
                      Return(k_msg.size())));

  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_session, handle_message(_));
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size()));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite,
       read_one_message_interactive_client_custom_interactive_timer) {
  config->m_timeouts.m_interactive_timeout = 11;
  sut->set_wait_timeout(config->m_timeouts.m_interactive_timeout);

  EXPECT_CALL(*mock_vio,
              set_timeout_in_ms(iface::Vio::Direction::k_read, 11 * 1000));
  EXPECT_CALL(*mock_vio, get_mysql_socket()).WillOnce(ReturnRef(m_socket));
  EXPECT_CALL(*mock_vio, read(_, _))
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end()),
                      Return(k_msg.size())));
  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size()));
  EXPECT_CALL(*mock_session, handle_message(_));
  EXPECT_CALL(*mock_wait_for_io, has_to_report_idle_waiting())
      .WillRepeatedly(Return(false));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite,
       read_one_message_non_interactive_client_custom_wait_timer) {
  config->m_timeouts.m_wait_timeout = 22;
  sut->set_wait_timeout(config->m_timeouts.m_wait_timeout);

  EXPECT_CALL(*mock_vio,
              set_timeout_in_ms(iface::Vio::Direction::k_read, 22 * 1000));
  EXPECT_CALL(*mock_vio, get_mysql_socket()).WillOnce(ReturnRef(m_socket));
  EXPECT_CALL(*mock_vio, read(_, _))
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end()),
                      Return(k_msg.size())));
  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_session, handle_message(_));
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size()));
  EXPECT_CALL(*mock_wait_for_io, has_to_report_idle_waiting())
      .WillRepeatedly(Return(false));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite, read_one_message_default_read_timeout) {
  EXPECT_CALL(*mock_vio, set_timeout_in_ms(
                             iface::Vio::Direction::k_read,
                             defaults::timeout::k_interactive_timeout * 1000));

  // Expected to be called twice - once for header and once for payload
  EXPECT_CALL(*mock_vio, read(_, _))
      .Times(2)
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end() - 1),
                      Return(k_msg.size() - 1)))
      .WillOnce(
          DoAll(SetArrayArgument<0>(k_msg.end() - 1, k_msg.end()), Return(1)));
  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_session, handle_message(_));
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size())).Times(1);

  auto conf = std::make_shared<ngs::Protocol_global_config>();
  EXPECT_CALL(mock_server, get_config()).WillRepeatedly(ReturnPointee(&conf));

  EXPECT_CALL(*mock_vio,
              set_timeout_in_ms(iface::Vio::Direction::k_read,
                                defaults::timeout::k_read_timeout * 1000));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite, read_one_message_custom_read_timeout) {
  config->m_timeouts.m_read_timeout = 33;
  sut->set_read_timeout(config->m_timeouts.m_read_timeout);

  EXPECT_CALL(*mock_vio, set_timeout_in_ms(
                             iface::Vio::Direction::k_read,
                             defaults::timeout::k_interactive_timeout * 1000));
  EXPECT_CALL(*mock_vio,
              set_timeout_in_ms(iface::Vio::Direction::k_read, 33 * 1000));
  EXPECT_CALL(*mock_vio, get_mysql_socket()).WillOnce(ReturnRef(m_socket));

  // Expected to be called twice - once for header and once for payload
  EXPECT_CALL(*mock_vio, read(_, _))
      .Times(2)
      .WillOnce(DoAll(SetArrayArgument<0>(k_msg.begin(), k_msg.end() - 1),
                      Return(k_msg.size() - 1)))
      .WillOnce(
          DoAll(SetArrayArgument<0>(k_msg.end() - 1, k_msg.end()), Return(1)));
  EXPECT_CALL(*mock_vio, set_state(_)).Times(2);
  EXPECT_CALL(*mock_session, handle_message(_));
  EXPECT_CALL(*mock_protocol_monitor, on_receive(k_msg.size())).Times(1);
  EXPECT_CALL(*mock_wait_for_io, has_to_report_idle_waiting())
      .WillRepeatedly(Return(false));

  auto conf = std::make_shared<ngs::Protocol_global_config>();
  EXPECT_CALL(mock_server, get_config()).WillRepeatedly(ReturnPointee(&conf));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite, read_one_message_failed_read) {
  EXPECT_CALL(*mock_vio, set_timeout_in_ms(
                             iface::Vio::Direction::k_read,
                             defaults::timeout::k_interactive_timeout * 1000));

  EXPECT_CALL(*mock_vio, read(_, _))
      .WillRepeatedly(SetSocketErrnoAndReturn(SOCKET_ETIMEDOUT, -1));
  EXPECT_CALL(*mock_vio, set_state(_)).Times(1);

  EXPECT_CALL(*mock_protocol_monitor, on_receive(_)).Times(0);
  EXPECT_CALL(*mock_session, set_proto(_));

  auto encoder = ngs::allocate_object<mock::Protocol_encoder>();
  ngs::Memory_block_pool memory_block_pool{{0, k_minimum_page_size}};
  protocol::Encoding_pool pool(0, &memory_block_pool);
  protocol::Encoding_buffer buffer(&pool);
  protocol::XMessage_encoder low_level_encoder(&buffer);
  ngs::Protocol_flusher flusher(&buffer, &low_level_encoder,
                                mock_protocol_monitor, mock_vio, [](int) {});
  EXPECT_CALL(*encoder, get_flusher()).WillRepeatedly(Return(&flusher));
  sut->set_encoder(encoder);

  // queue up notice for future send
  EXPECT_CALL(mock_notice_output_queue, emplace(_));

  sut->read_one_message_and_dispatch();
}

TEST_F(Timers_test_suite, send_message_default_write_timeout) {
  EXPECT_CALL(*mock_vio, get_fd());
  Expectation set_timeout_exp = EXPECT_CALL(
      *mock_vio, set_timeout_in_ms(iface::Vio::Direction::k_write,
                                   defaults::timeout::k_write_timeout * 1000));

  EXPECT_CALL(*mock_vio, write(_, _)).After(set_timeout_exp);
  EXPECT_CALL(*mock_session, set_proto(_));

  auto stub_error_handler = [](int) {};
  auto encoder = ngs::allocate_object<ngs::Protocol_encoder>(
      mock_vio, stub_error_handler, mock_protocol_monitor, &m_pool);
  sut->set_encoder(encoder);
  encoder->send_protobuf_message(Mysqlx::ServerMessages::OK, Mysqlx::Ok(),
                                 false);
}

TEST_F(Timers_test_suite, send_message_custom_write_timeout) {
  config->m_timeouts.m_write_timeout = 44;
  sut->set_write_timeout(config->m_timeouts.m_write_timeout);

  EXPECT_CALL(*mock_session, set_proto(_));

  EXPECT_CALL(*mock_vio, get_fd());
  Expectation set_timeout_exp = EXPECT_CALL(
      *mock_vio, set_timeout_in_ms(iface::Vio::Direction::k_write, 44 * 1000));

  EXPECT_CALL(*mock_vio, write(_, _)).After(set_timeout_exp);

  auto stub_error_handler = [](int) {};
  auto encoder = ngs::allocate_object<ngs::Protocol_encoder>(
      mock_vio, stub_error_handler, mock_protocol_monitor, &m_pool);
  sut->set_encoder(encoder);
  encoder->send_protobuf_message(Mysqlx::ServerMessages::OK, Mysqlx::Ok(),
                                 false);
}

TEST_F(Timers_test_suite, send_message_failed_write) {
  EXPECT_CALL(*mock_vio, get_fd());
  EXPECT_CALL(*mock_vio,
              set_timeout_in_ms(iface::Vio::Direction::k_write,
                                defaults::timeout::k_write_timeout * 1000));

  ON_CALL(*mock_vio, write(_, _)).WillByDefault(Return(-1));
  EXPECT_CALL(*mock_vio, write(_, _));
  EXPECT_CALL(*mock_session, set_proto(_));

  struct CustomExpection {};
  auto stub_error_handler = [](int) { throw CustomExpection(); };
  auto encoder = ngs::allocate_object<ngs::Protocol_encoder>(
      mock_vio, stub_error_handler, mock_protocol_monitor, &m_pool);
  sut->set_encoder(encoder);

  // write failed so error_handler should be used
  EXPECT_THROW(encoder->send_protobuf_message(Mysqlx::ServerMessages::OK,
                                              Mysqlx::Ok(), false),
               CustomExpection);
}

}  // namespace test
}  // namespace xpl
