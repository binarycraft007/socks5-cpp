#include "asio_config.hpp"
#include "socks5/client.hpp"
#include "socks5/server.hpp"

#include <gtest/gtest.h>
#include <thread>

using namespace socks5;

class IntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Find free ports (simplistic approach)
        proxy_port_ = 10800 + (std::rand() % 1000);
        target_port_ = 20800 + (std::rand() % 1000);
    }

    uint16_t proxy_port_;
    uint16_t target_port_;
};

// Simple Echo Server to act as the final destination
asio::awaitable<void> echo_server(asio::ip::tcp::acceptor& acceptor) {
    auto socket = co_await acceptor.async_accept(asio::use_awaitable);
    try {
        char data[1024];
        while (true) {
            size_t n = co_await socket.async_read_some(asio::buffer(data), asio::use_awaitable);
            co_await asio::async_write(socket, asio::buffer(data, n), asio::use_awaitable);
        }
    } catch (...) {
    }
}

TEST_F(IntegrationTest, ConnectAndEcho) {
    asio::io_context io_ctx;

    // 1. Start SOCKS5 Server
    Server proxy_server(io_ctx, proxy_port_, "127.0.0.1");
    proxy_server.start();

    // 2. Start Target Echo Server
    asio::ip::tcp::acceptor target_acceptor(io_ctx, {asio::ip::tcp::v4(), target_port_});
    asio::co_spawn(io_ctx, echo_server(target_acceptor), asio::detached);

    // 3. Client Logic
    asio::co_spawn(
        io_ctx,
        [&]() -> asio::awaitable<void> {
            asio::ip::tcp::socket socket(io_ctx);

            // Connect via Proxy
            try {
                co_await Client::connect(socket, {asio::ip::make_address("127.0.0.1"), proxy_port_}, "127.0.0.1",
                                         target_port_);

                // Send Hello
                std::string msg = "Hello SOCKS5";
                co_await asio::async_write(socket, asio::buffer(msg), asio::use_awaitable);

                // Read Echo
                char buf[1024];
                size_t n = co_await socket.async_read_some(asio::buffer(buf), asio::use_awaitable);
                std::string reply(buf, n);

                EXPECT_EQ(msg, reply);

            } catch (std::exception& e) {
                ADD_FAILURE() << "Client error: " << e.what();
                co_return;
            }

            io_ctx.stop();
        },
        asio::detached);

    io_ctx.run_for(std::chrono::seconds(2));
}
