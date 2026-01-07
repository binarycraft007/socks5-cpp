#include "asio_config.hpp"
#include "socks5/protocol.hpp"
#include "socks5/server.hpp"

#include <atomic>
#include <gtest/gtest.h>
#include <thread>

using namespace socks5;

class ComplianceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        server_port_ = 10000 + (std::rand() % 5000);

        // Use a work guard to keep run() alive until we explicitly stop it
        server_thread_ = std::thread([this]() {
            auto work_guard = asio::make_work_guard(server_io_context_);
            try {
                Server server(server_io_context_, server_port_, "127.0.0.1");
                server.start();
                server_io_context_.run();
            } catch (...) {
            }
        });

        // Wait for port to be listening (simple poll)
        asio::io_context client_io;
        for (int i = 0; i < 50; ++i) {
            try {
                asio::ip::tcp::socket s(client_io);
                s.connect({asio::ip::make_address("127.0.0.1"), server_port_});
                break;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }

    void TearDown() override {
        server_io_context_.stop();
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    void RawHandshake(asio::ip::tcp::socket& socket, uint8_t ver, const std::vector<uint8_t>& methods,
                      std::vector<uint8_t>& response) {
        std::vector<uint8_t> req;
        req.push_back(ver);
        req.push_back(static_cast<uint8_t>(methods.size()));
        req.insert(req.end(), methods.begin(), methods.end());
        asio::write(socket, asio::buffer(req));

        response.resize(2);
        asio::read(socket, asio::buffer(response));
    }

    uint16_t server_port_;
    asio::io_context server_io_context_;
    std::thread server_thread_;
};

// 1. Version Negotiation
TEST_F(ComplianceTest, InvalidVersion) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    // Send Version 4
    uint8_t req[] = {0x04, 0x01, 0x00};
    asio::write(socket, asio::buffer(req));

    uint8_t resp[2];
    std::error_code ec;
    asio::read(socket, asio::buffer(resp), ec);

    // Server should close connection.
    // This can manifest as EOF (clean close) or Connection Reset (abrupt close).
    EXPECT_TRUE(ec == asio::error::eof || ec == asio::error::connection_reset)
        << "Unexpected error code: " << ec.message();
}

// 2. No Acceptable Auth
TEST_F(ComplianceTest, NoAcceptableAuth) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    // Methods: USER/PASS (0x02) only. Server only supports NO_AUTH (0x00).
    std::vector<uint8_t> methods = {0x02};
    std::vector<uint8_t> resp;

    RawHandshake(socket, 0x05, methods, resp);

    ASSERT_EQ(resp.size(), 2);
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], 0xFF); // NO ACCEPTABLE METHODS
}

// 3. Successful Auth Selection
TEST_F(ComplianceTest, SelectsNoAuth) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    std::vector<uint8_t> methods = {0x02, 0x00};
    std::vector<uint8_t> resp;

    RawHandshake(socket, 0x05, methods, resp);

    ASSERT_EQ(resp.size(), 2);
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], 0x00); // Selected NO_AUTH
}

// 4. Request: Unsupported Command
TEST_F(ComplianceTest, UnsupportedCommand) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    std::vector<uint8_t> methods = {0x00};
    std::vector<uint8_t> auth_resp;
    RawHandshake(socket, 0x05, methods, auth_resp);
    ASSERT_EQ(auth_resp[1], 0x00);

    // Send Request: BIND (0x02)
    uint8_t req[] = {0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80};
    asio::write(socket, asio::buffer(req));

    uint8_t resp[10];
    asio::read(socket, asio::buffer(resp));

    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], 0x07); // COMMAND_NOT_SUPPORTED
}

// 5. Request: Unsupported Address Type
TEST_F(ComplianceTest, UnsupportedAddressType) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    std::vector<uint8_t> methods = {0x00};
    std::vector<uint8_t> auth_resp;
    RawHandshake(socket, 0x05, methods, auth_resp);

    // Send Request: ATYP 0x05 (Invalid)
    uint8_t req[] = {0x05, 0x01, 0x00, 0x05, 0, 0};
    asio::write(socket, asio::buffer(req));

    uint8_t resp[10];
    asio::read(socket, asio::buffer(resp));

    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], 0x08); // ADDRESS_TYPE_NOT_SUPPORTED
}

// 6. Connect Failure
TEST_F(ComplianceTest, ConnectionRefused) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    std::vector<uint8_t> dummy_resp;
    RawHandshake(socket, 0x05, {0x00}, dummy_resp);

    // Connect to port 1 on localhost (should be refused)
    uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1};
    asio::write(socket, asio::buffer(req));

    uint8_t resp[10];
    asio::read(socket, asio::buffer(resp));

    EXPECT_EQ(resp[0], 0x05);
    EXPECT_NE(resp[1], 0x00); // Not Success
}

// 7. Domain Name Connect
TEST_F(ComplianceTest, DomainNameConnect) {
    asio::io_context io;
    asio::ip::tcp::acceptor target(io, {asio::ip::tcp::v4(), 0});
    uint16_t target_port = target.local_endpoint().port();

    // Use a promise to signal when the target has accepted a connection
    std::promise<void> accepted_promise;
    auto accepted_future = accepted_promise.get_future();

    std::thread target_thread([&]() {
        try {
            auto s = target.accept();
            accepted_promise.set_value();
        } catch (...) {
        }
    });

    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    std::vector<uint8_t> dummy;
    RawHandshake(socket, 0x05, {0x00}, dummy);

    std::string domain = "localhost";
    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x03};
    req.push_back(static_cast<uint8_t>(domain.size()));
    req.insert(req.end(), domain.begin(), domain.end());
    req.push_back((target_port >> 8) & 0xFF);
    req.push_back(target_port & 0xFF);

    asio::write(socket, asio::buffer(req));

    uint8_t resp[1024];
    asio::read(socket, asio::buffer(resp, 4));
    EXPECT_EQ(resp[1], 0x00);

    // Ensure connection actually reached target
    accepted_future.wait();

    target_thread.join();
}
