#pragma once

#include "asio_config.hpp"

#include <cstdint>
#include <string>

namespace socks5 {

class Server {
  public:
    // Bind to specific IP (default 0.0.0.0)
    Server(asio::io_context& io_context, uint16_t port, const std::string& ip_address = "0.0.0.0");

    void start();

  private:
    asio::awaitable<void> listen();
    asio::awaitable<void> handle_session(asio::ip::tcp::socket client_socket);
    asio::awaitable<void> relay(asio::ip::tcp::socket& from, asio::ip::tcp::socket& to);
    asio::awaitable<void> relay_udp(asio::ip::tcp::socket& control_socket, asio::ip::udp::socket udp_socket,
                                    asio::ip::address client_ip);

    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::string listen_ip_;
};

} // namespace socks5
