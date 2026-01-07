#pragma once

#include "asio_config.hpp"
#include "socks5/protocol.hpp"

#include <string>

namespace socks5 {

class Client {
  public:
    // Connects to the proxy, performs handshake, and requests connection to target.
    // Returns the connected socket ready for data transfer.
    static asio::awaitable<void> connect(asio::ip::tcp::socket& socket, const asio::ip::tcp::endpoint& proxy_endpoint,
                                         const std::string& target_host, uint16_t target_port);

    // Assumes socket is already connected to proxy. Performs SOCKS5 handshake.
    static asio::awaitable<void> handshake(asio::ip::tcp::socket& socket, const std::string& target_host,
                                           uint16_t target_port);
};

} // namespace socks5
