#include "asio_config.hpp"
#include "socks5/protocol.hpp"
#include "socks5/server.hpp"

#include <future>
#include <gtest/gtest.h>
#include <thread>

using namespace socks5;

class UdpTest : public ::testing::Test {
  protected:
    void SetUp() override {
        server_port_ = 10000 + (std::rand() % 5000);
        server_thread_ = std::thread([this]() {
            auto work_guard = asio::make_work_guard(server_io_context_);
            try {
                Server server(server_io_context_, server_port_, "127.0.0.1");
                server.start();
                server_io_context_.run();
            } catch (...) {
            }
        });

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

    uint16_t server_port_;
    asio::io_context server_io_context_;
    std::thread server_thread_;
};

// Test UDP ASSOCIATE
TEST_F(UdpTest, UdpAssociateAndEcho) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), server_port_});

    // 1. Handshake
    uint8_t handshake[] = {0x05, 0x01, 0x00};
    asio::write(socket, asio::buffer(handshake));
    uint8_t h_resp[2];
    asio::read(socket, asio::buffer(h_resp));
    ASSERT_EQ(h_resp[1], 0x00);

    // 2. Request UDP ASSOCIATE
    // Client wants to associate. Client IP/Port is irrelevant usually (0.0.0.0:0)
    std::vector<uint8_t> req = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    asio::write(socket, asio::buffer(req));

    // 3. Receive Reply with BND.ADDR/PORT
    uint8_t resp[10];
    asio::read(socket, asio::buffer(resp));
    ASSERT_EQ(resp[1], 0x00); // Success
    ASSERT_EQ(resp[3], 0x01); // IPv4

    // Extract UDP Relay Port
    uint16_t relay_port = (resp[8] << 8) | resp[9];
    asio::ip::udp::endpoint relay_ep(asio::ip::make_address("127.0.0.1"), relay_port);

    // 4. Start Target Echo UDP Server
    asio::ip::udp::socket target_socket(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
    uint16_t target_port = target_socket.local_endpoint().port();

    std::thread target_thread([&]() {
        try {
            char buf[1024];
            asio::ip::udp::endpoint sender;
            size_t n = target_socket.receive_from(asio::buffer(buf), sender);
            target_socket.send_to(asio::buffer(buf, n), sender);
        } catch (...) {
        }
    });

    // 5. Send UDP Packet to Relay
    // Encapsulate: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
    std::vector<uint8_t> packet = {0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1};
    packet.push_back((target_port >> 8) & 0xFF);
    packet.push_back(target_port & 0xFF);
    std::string msg = "Hello UDP";
    packet.insert(packet.end(), msg.begin(), msg.end());

    asio::ip::udp::socket client_udp(io);
    client_udp.open(asio::ip::udp::v4());

    // IMPORTANT: We must bind client_udp to the same IP family, and the server
    // implementation checks if sender_ip == tcp_client_ip.
    // Since we are localhost, it should match.

    client_udp.send_to(asio::buffer(packet), relay_ep);

    // 6. Receive Echo Reply from Relay
    uint8_t recv_buf[1024];
    asio::ip::udp::endpoint sender;
    size_t n = client_udp.receive_from(asio::buffer(recv_buf), sender);

    // Verify SOCKS5 Header in reply
    // RSV(2) FRAG(1) ATYP(1) ...
    EXPECT_EQ(recv_buf[0], 0x00);
    EXPECT_EQ(recv_buf[1], 0x00);
    EXPECT_EQ(recv_buf[2], 0x00);
    EXPECT_EQ(recv_buf[3], 0x01); // IPv4 source

    // Skip header (10 bytes for IPv4)
    std::string reply_msg(reinterpret_cast<char*>(&recv_buf[10]), n - 10);
    EXPECT_EQ(reply_msg, msg);

    target_thread.join();
}
