#include "socks5/client.hpp"

namespace socks5 {

asio::awaitable<void> Client::connect(asio::ip::tcp::socket& socket, const asio::ip::tcp::endpoint& proxy_endpoint,
                                      const std::string& target_host, uint16_t target_port) {
    co_await socket.async_connect(proxy_endpoint, asio::use_awaitable);
    co_await handshake(socket, target_host, target_port);
}

asio::awaitable<void> Client::handshake(asio::ip::tcp::socket& socket, const std::string& target_host,
                                        uint16_t target_port) {
    // 1. Send Version + Auth Methods (No Auth)
    uint8_t handshake_req[] = {VERSION, 0x01, static_cast<uint8_t>(AuthMethod::NO_AUTH)};
    co_await asio::async_write(socket, asio::buffer(handshake_req), asio::use_awaitable);

    // 2. Receive Auth Selection
    uint8_t handshake_resp[2];
    co_await asio::async_read(socket, asio::buffer(handshake_resp), asio::use_awaitable);

    if (handshake_resp[0] != VERSION) {
        throw std::system_error(make_error_code(Error::INVALID_VERSION));
    }
    if (static_cast<AuthMethod>(handshake_resp[1]) == AuthMethod::NO_ACCEPTABLE) {
        throw std::system_error(make_error_code(Error::NO_ACCEPTABLE_AUTH));
    }
    if (static_cast<AuthMethod>(handshake_resp[1]) != AuthMethod::NO_AUTH) {
        // We only support NO_AUTH for this simple client
        throw std::system_error(make_error_code(Error::NO_ACCEPTABLE_AUTH));
    }

    // 3. Send Request (Connect)
    std::vector<uint8_t> request;
    request.push_back(VERSION);
    request.push_back(static_cast<uint8_t>(Command::CONNECT));
    request.push_back(RSV);

    // Determine address type
    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(target_host, ec);

    if (!ec) {
        if (ip_addr.is_v4()) {
            request.push_back(static_cast<uint8_t>(AddressType::IPV4));
            auto bytes = ip_addr.to_v4().to_bytes();
            request.insert(request.end(), bytes.begin(), bytes.end());
        } else {
            request.push_back(static_cast<uint8_t>(AddressType::IPV6));
            auto bytes = ip_addr.to_v6().to_bytes();
            request.insert(request.end(), bytes.begin(), bytes.end());
        }
    } else {
        // Domain name
        request.push_back(static_cast<uint8_t>(AddressType::DOMAIN_NAME));
        if (target_host.size() > 255) {
            throw std::system_error(make_error_code(Error::INVALID_FORMAT));
        }
        request.push_back(static_cast<uint8_t>(target_host.size()));
        request.insert(request.end(), target_host.begin(), target_host.end());
    }

    // Port (Network Byte Order)
    request.push_back(static_cast<uint8_t>((target_port >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>(target_port & 0xFF));

    co_await asio::async_write(socket, asio::buffer(request), asio::use_awaitable);

    // 4. Receive Reply
    // Read header first: VER, REP, RSV, ATYP
    uint8_t reply_header[4];
    co_await asio::async_read(socket, asio::buffer(reply_header), asio::use_awaitable);

    if (reply_header[0] != VERSION) {
        throw std::system_error(make_error_code(Error::INVALID_VERSION));
    }

    Reply rep = static_cast<Reply>(reply_header[1]);
    if (rep != Reply::SUCCEEDED) {
        // Map SOCKS5 errors to system_error or custom
        throw std::system_error(make_error_code(Error::CONNECTION_FAILED));
    }

    AddressType atyp = static_cast<AddressType>(reply_header[3]);

    // Read remaining address/port to clear the buffer
    if (atyp == AddressType::IPV4) {
        uint8_t buf[6]; // 4 IP + 2 Port
        co_await asio::async_read(socket, asio::buffer(buf), asio::use_awaitable);
    } else if (atyp == AddressType::IPV6) {
        uint8_t buf[18]; // 16 IP + 2 Port
        co_await asio::async_read(socket, asio::buffer(buf), asio::use_awaitable);
    } else if (atyp == AddressType::DOMAIN_NAME) {
        uint8_t len;
        co_await asio::async_read(socket, asio::buffer(&len, 1), asio::use_awaitable);
        std::vector<uint8_t> buf(len + 2); // Domain + 2 Port
        co_await asio::async_read(socket, asio::buffer(buf), asio::use_awaitable);
    } else {
        throw std::system_error(make_error_code(Error::UNSUPPORTED_ADDRESS_TYPE));
    }
}

} // namespace socks5
