#include "socks5/server.hpp"

#include "socks5/protocol.hpp"
#include "socks5/timeout.hpp"

#include <chrono>
#include <print>
#include <vector>

using namespace asio::experimental::awaitable_operators;
using namespace std::chrono_literals;

namespace socks5 {

constexpr auto HANDSHAKE_TIMEOUT = 10s;
constexpr auto IDLE_TIMEOUT = 300s;

Server::Server(asio::io_context& io_context, uint16_t port, const std::string& ip_address)
    : io_context_(io_context), acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::make_address(ip_address), port)),
      listen_ip_(ip_address) {}

void Server::start() {
    asio::co_spawn(io_context_, listen(), asio::detached);
}

asio::awaitable<void> Server::listen() {
    try {
        while (true) {
            auto [ec, socket] = co_await acceptor_.async_accept(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                std::println(stderr, "Accept failed: {}", ec.message());
                continue;
            }
            asio::co_spawn(io_context_, handle_session(std::move(socket)), asio::detached);
        }
    } catch (std::exception& e) {
        std::println(stderr, "Listen loop error: {}", e.what());
    }
}

asio::awaitable<void> Server::handle_session(asio::ip::tcp::socket client_socket) {
    // 1. Handshake
    uint8_t version;
    auto read_ver = co_await with_timeout_nothrow<size_t>(
        asio::async_read(client_socket, asio::buffer(&version, 1), asio::as_tuple(asio::use_awaitable)),
        HANDSHAKE_TIMEOUT);
    if (!read_ver)
        co_return;

    if (version != VERSION)
        co_return;

    uint8_t nmethods;
    auto read_nm = co_await with_timeout_nothrow<size_t>(
        asio::async_read(client_socket, asio::buffer(&nmethods, 1), asio::as_tuple(asio::use_awaitable)),
        HANDSHAKE_TIMEOUT);
    if (!read_nm)
        co_return;

    std::vector<uint8_t> methods(nmethods);
    auto read_methods = co_await with_timeout_nothrow<size_t>(
        asio::async_read(client_socket, asio::buffer(methods), asio::as_tuple(asio::use_awaitable)), HANDSHAKE_TIMEOUT);
    if (!read_methods)
        co_return;

    bool no_auth_supported = false;
    for (auto m : methods) {
        if (static_cast<AuthMethod>(m) == AuthMethod::NO_AUTH) {
            no_auth_supported = true;
            break;
        }
    }

    if (!no_auth_supported) {
        uint8_t resp[] = {VERSION, static_cast<uint8_t>(AuthMethod::NO_ACCEPTABLE)};
        co_await asio::async_write(client_socket, asio::buffer(resp), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    uint8_t resp[] = {VERSION, static_cast<uint8_t>(AuthMethod::NO_AUTH)};
    auto write_auth = co_await with_timeout_nothrow<size_t>(
        asio::async_write(client_socket, asio::buffer(resp), asio::as_tuple(asio::use_awaitable)), HANDSHAKE_TIMEOUT);
    if (!write_auth)
        co_return;

    // 2. Request
    uint8_t req_header[4];
    auto read_req = co_await with_timeout_nothrow<size_t>(
        asio::async_read(client_socket, asio::buffer(req_header), asio::as_tuple(asio::use_awaitable)),
        HANDSHAKE_TIMEOUT);
    if (!read_req)
        co_return;

    if (req_header[0] != VERSION)
        co_return;
    Command cmd = static_cast<Command>(req_header[1]);
    AddressType atyp = static_cast<AddressType>(req_header[3]);

    // Consume address fields even if we don't use them for UDP_ASSOCIATE right away
    // RFC: UDP ASSOCIATE DST.ADDR/PORT are the address the client expects to send FROM.
    // We generally allow any, or strict check. For now, just read and ignore (allow any).

    std::string target_host;
    std::string target_port_str;

    if (atyp == AddressType::IPV4) {
        asio::ip::address_v4::bytes_type bytes;
        auto read_ip = co_await with_timeout_nothrow<size_t>(
            asio::async_read(client_socket, asio::buffer(bytes), asio::as_tuple(asio::use_awaitable)),
            HANDSHAKE_TIMEOUT);
        if (!read_ip)
            co_return;
        target_host = asio::ip::make_address_v4(bytes).to_string();
    } else if (atyp == AddressType::DOMAIN_NAME) {
        uint8_t len;
        auto read_len = co_await with_timeout_nothrow<size_t>(
            asio::async_read(client_socket, asio::buffer(&len, 1), asio::as_tuple(asio::use_awaitable)),
            HANDSHAKE_TIMEOUT);
        if (!read_len)
            co_return;
        target_host.resize(len);
        auto read_domain = co_await with_timeout_nothrow<size_t>(
            asio::async_read(client_socket, asio::buffer(target_host), asio::as_tuple(asio::use_awaitable)),
            HANDSHAKE_TIMEOUT);
        if (!read_domain)
            co_return;
    } else if (atyp == AddressType::IPV6) {
        asio::ip::address_v6::bytes_type bytes;
        auto read_ip6 = co_await with_timeout_nothrow<size_t>(
            asio::async_read(client_socket, asio::buffer(bytes), asio::as_tuple(asio::use_awaitable)),
            HANDSHAKE_TIMEOUT);
        if (!read_ip6)
            co_return;
        target_host = asio::ip::make_address_v6(bytes).to_string();
    } else {
        uint8_t err_resp[] = {
            VERSION, static_cast<uint8_t>(Reply::ADDRESS_TYPE_NOT_SUPPORTED), RSV, 0x01, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(client_socket, asio::buffer(err_resp), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    uint8_t port_bytes[2];
    auto read_port = co_await with_timeout_nothrow<size_t>(
        asio::async_read(client_socket, asio::buffer(port_bytes, 2), asio::as_tuple(asio::use_awaitable)),
        HANDSHAKE_TIMEOUT);
    if (!read_port)
        co_return;
    uint16_t port = static_cast<uint16_t>((port_bytes[0] << 8) | port_bytes[1]);
    target_port_str = std::to_string(port);

    // Handle Commands
    if (cmd == Command::UDP_ASSOCIATE) {
        // Create UDP socket on ANY port, same IP family as control connection preferably, or just v4/v6 dual stack if
        // possible. For simplicity, we bind to the same IP version as the acceptor or just V4. Let's use the local
        // address of the client connection to determine family.
        auto local_ep_tcp = client_socket.local_endpoint();
        asio::ip::udp::endpoint udp_bind_ep(local_ep_tcp.address(), 0);

        asio::ip::udp::socket udp_socket(client_socket.get_executor());
        asio::error_code ec;
        udp_socket.open(udp_bind_ep.protocol(), ec);
        if (!ec)
            udp_socket.bind(udp_bind_ep, ec);

        if (ec) {
            uint8_t err_resp[] = {VERSION, static_cast<uint8_t>(Reply::GENERIC_FAILURE), RSV, 0x01, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(client_socket, asio::buffer(err_resp), asio::as_tuple(asio::use_awaitable));
            co_return;
        }

        auto udp_local_ep = udp_socket.local_endpoint(ec);

        // Reply with BND.ADDR/PORT
        std::vector<uint8_t> success_resp;
        success_resp.push_back(VERSION);
        success_resp.push_back(static_cast<uint8_t>(Reply::SUCCEEDED));
        success_resp.push_back(RSV);

        if (udp_local_ep.address().is_v4()) {
            success_resp.push_back(static_cast<uint8_t>(AddressType::IPV4));
            auto bytes = udp_local_ep.address().to_v4().to_bytes();
            success_resp.insert(success_resp.end(), bytes.begin(), bytes.end());
        } else {
            success_resp.push_back(static_cast<uint8_t>(AddressType::IPV6));
            auto bytes = udp_local_ep.address().to_v6().to_bytes();
            success_resp.insert(success_resp.end(), bytes.begin(), bytes.end());
        }

        uint16_t bound_port = udp_local_ep.port();
        success_resp.push_back(static_cast<uint8_t>((bound_port >> 8) & 0xFF));
        success_resp.push_back(static_cast<uint8_t>(bound_port & 0xFF));

        auto write_success = co_await with_timeout_nothrow<size_t>(
            asio::async_write(client_socket, asio::buffer(success_resp), asio::as_tuple(asio::use_awaitable)),
            HANDSHAKE_TIMEOUT);
        if (!write_success)
            co_return;

        // Start UDP Relay
        auto client_peer_ep = client_socket.remote_endpoint(ec);
        if (ec)
            co_return;

        co_await relay_udp(client_socket, std::move(udp_socket), client_peer_ep.address());
        co_return;
    } else if (cmd != Command::CONNECT) {
        uint8_t err_resp[] = {VERSION, static_cast<uint8_t>(Reply::COMMAND_NOT_SUPPORTED), RSV, 0x01, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(client_socket, asio::buffer(err_resp), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    // 3. Connect to Target
    asio::ip::tcp::resolver resolver(client_socket.get_executor());
    asio::ip::tcp::socket target_socket(client_socket.get_executor());

    auto endpoints_result = co_await with_timeout_nothrow<asio::ip::tcp::resolver::results_type>(
        resolver.async_resolve(target_host, target_port_str, asio::as_tuple(asio::use_awaitable)), HANDSHAKE_TIMEOUT);

    if (!endpoints_result) {
        uint8_t err_resp[] = {VERSION, static_cast<uint8_t>(Reply::HOST_UNREACHABLE), RSV, 0x01, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(client_socket, asio::buffer(err_resp), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    auto connect_result = co_await with_timeout_nothrow<asio::ip::tcp::endpoint>(
        asio::async_connect(target_socket, *endpoints_result, asio::as_tuple(asio::use_awaitable)), HANDSHAKE_TIMEOUT);

    if (!connect_result) {
        uint8_t err_resp[] = {VERSION, static_cast<uint8_t>(Reply::CONNECTION_REFUSED), RSV, 0x01, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(client_socket, asio::buffer(err_resp), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    // 4. Send Success Reply
    asio::error_code ec;
    auto local_ep = target_socket.local_endpoint(ec);

    std::vector<uint8_t> success_resp;
    success_resp.push_back(VERSION);
    success_resp.push_back(static_cast<uint8_t>(Reply::SUCCEEDED));
    success_resp.push_back(RSV);

    if (!ec && local_ep.address().is_v4()) {
        success_resp.push_back(static_cast<uint8_t>(AddressType::IPV4));
        auto bytes = local_ep.address().to_v4().to_bytes();
        success_resp.insert(success_resp.end(), bytes.begin(), bytes.end());
    } else if (!ec && local_ep.address().is_v6()) {
        success_resp.push_back(static_cast<uint8_t>(AddressType::IPV6));
        auto bytes = local_ep.address().to_v6().to_bytes();
        success_resp.insert(success_resp.end(), bytes.begin(), bytes.end());
    } else {
        // Fallback to 0.0.0.0 if error or unknown
        success_resp.push_back(static_cast<uint8_t>(AddressType::IPV4));
        success_resp.push_back(0);
        success_resp.push_back(0);
        success_resp.push_back(0);
        success_resp.push_back(0);
    }

    uint16_t bound_port = (!ec) ? local_ep.port() : 0;
    success_resp.push_back(static_cast<uint8_t>((bound_port >> 8) & 0xFF));
    success_resp.push_back(static_cast<uint8_t>(bound_port & 0xFF));

    auto write_success = co_await with_timeout_nothrow<size_t>(
        asio::async_write(client_socket, asio::buffer(success_resp), asio::as_tuple(asio::use_awaitable)),
        HANDSHAKE_TIMEOUT);
    if (!write_success)
        co_return;

    // 5. Relay (Zig-style error propagation)
    co_await (relay(client_socket, target_socket) && relay(target_socket, client_socket));
}

asio::awaitable<void> Server::relay(asio::ip::tcp::socket& from, asio::ip::tcp::socket& to) {
    std::array<uint8_t, 8192> buffer;
    while (true) {
        // Read
        auto read_res = co_await with_timeout_nothrow<size_t>(
            from.async_read_some(asio::buffer(buffer), asio::as_tuple(asio::use_awaitable)), IDLE_TIMEOUT);

        if (!read_res) {
            // E.g. EOF or Timeout or Reset
            break;
        }
        size_t n = *read_res;

        // Write
        auto write_res = co_await with_timeout_nothrow<size_t>(
            asio::async_write(to, asio::buffer(buffer, n), asio::as_tuple(asio::use_awaitable)), IDLE_TIMEOUT);

        if (!write_res) {
            break;
        }
    }

    // Cleanup: Close both ends
    asio::error_code ec;
    from.close(ec);
    to.close(ec);
    co_return; // Important: explicit return for void awaitable if not falling off end
}

asio::awaitable<void> Server::relay_udp(asio::ip::tcp::socket& control_socket, asio::ip::udp::socket udp_socket,
                                        asio::ip::address client_ip) {
    std::array<uint8_t, 65536> buffer;
    asio::ip::udp::endpoint sender_ep;
    asio::ip::udp::endpoint last_client_ep;
    uint16_t client_port = 0; // Learned from first packet

    // Resolution Cache
    std::string cached_host;
    std::string cached_port_str;
    asio::ip::udp::endpoint cached_target_ep;
    bool has_cached_target = false;

    // Reuse resolver
    asio::ip::udp::resolver resolver(control_socket.get_executor());

    try {
        while (true) {
            char dummy;
            auto race_result = co_await (
                udp_socket.async_receive_from(asio::buffer(buffer), sender_ep, asio::as_tuple(asio::use_awaitable)) ||
                control_socket.async_read_some(asio::buffer(&dummy, 1), asio::as_tuple(asio::use_awaitable)));

            if (race_result.index() == 1)
                break; // TCP closed

            auto& [ec, n] = std::get<0>(race_result);
            if (ec || n == 0)
                continue;

            bool is_from_client = false;

            if (sender_ep.address() == client_ip) {
                if (client_port == 0) {
                    client_port = sender_ep.port();
                    is_from_client = true;
                } else if (sender_ep.port() == client_port) {
                    is_from_client = true;
                } else {
                    is_from_client = false;
                }
            } else {
                is_from_client = false;
            }

            if (is_from_client) {
                // Packet from Client -> Forward to Target
                last_client_ep = sender_ep;

                if (n < 10)
                    continue;
                if (buffer[0] != 0x00 || buffer[1] != 0x00)
                    continue;
                if (buffer[2] != 0x00)
                    continue; // Drop fragmented

                size_t header_len = 0;
                AddressType atyp = static_cast<AddressType>(buffer[3]);

                // We need to parse destination to check cache
                // Pointers to the raw data in buffer to avoid string copy if possible,
                // but for cache comparison we might need string or carefully compare bytes.
                // For simplicity and safety, we parse.

                std::string current_host;     // Use string to own the data (prevents dangling view)
                std::string current_port_str; // Need storage for conversion

                if (atyp == AddressType::IPV4) {
                    header_len = 10;
                    if (n < header_len)
                        continue;
                    // Optimization: Check if bytes match cached bytes?
                    // Actually, constructing IP object is fast.
                    asio::ip::address_v4::bytes_type bytes;
                    std::memcpy(bytes.data(), &buffer[4], 4);
                    // Convert to string for cache key? Or store address object?
                    // Let's stick to string for generic resolver support, but could optimize further.
                    // Ideally we avoid to_string() if matches cache.
                    // Let's just do full parse for now, optimize resolve.
                    current_host = asio::ip::make_address_v4(bytes).to_string();
                } else if (atyp == AddressType::IPV6) {
                    header_len = 22;
                    if (n < header_len)
                        continue;
                    asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), &buffer[4], 16);
                    current_host = asio::ip::make_address_v6(bytes).to_string();
                } else if (atyp == AddressType::DOMAIN_NAME) {
                    uint8_t dlen = buffer[4];
                    header_len = 5 + static_cast<size_t>(dlen) + 2;
                    if (n < header_len)
                        continue;
                    current_host = std::string(reinterpret_cast<char*>(&buffer[5]), dlen);
                } else {
                    continue;
                }

                size_t port_idx = header_len - 2;
                uint16_t port_nbo = static_cast<uint16_t>((buffer[port_idx] << 8) | buffer[port_idx + 1]);
                // Optimization: integer compare is faster than string compare.
                // But resolver needs string.

                // Better: cache the uint16_t port
                static uint16_t cached_port_int = 0;
                if (has_cached_target && port_nbo == cached_port_int && current_host == cached_host) {
                    // Hit
                } else {
                    // Miss
                    cached_host = std::string(current_host);
                    cached_port_int = port_nbo;
                    cached_port_str = std::to_string(port_nbo);

                    auto [rec, endpoints] = co_await resolver.async_resolve(cached_host, cached_port_str,
                                                                            asio::as_tuple(asio::use_awaitable));
                    if (!rec && endpoints.begin() != endpoints.end()) {
                        cached_target_ep = *endpoints.begin();
                        has_cached_target = true;
                    } else {
                        has_cached_target = false;
                    }
                }

                if (has_cached_target) {
                    auto payload = asio::buffer(&buffer[header_len], n - header_len);
                    co_await udp_socket.async_send_to(payload, cached_target_ep, asio::as_tuple(asio::use_awaitable));
                }

            } else {
                // Packet from Target -> Forward to Client
                if (client_port == 0)
                    continue;

                // Encapsulate with Stack Buffer
                // Max header: 4 (IPv4) or 16 (IPv6) + 6 overhead = 22 bytes.
                // Let's use 24 bytes fixed array.
                uint8_t header_buf[24];
                size_t h_len = 0;

                header_buf[0] = 0x00;
                header_buf[1] = 0x00; // RSV
                header_buf[2] = 0x00; // FRAG

                if (sender_ep.address().is_v4()) {
                    header_buf[3] = static_cast<uint8_t>(AddressType::IPV4);
                    auto bytes = sender_ep.address().to_v4().to_bytes();
                    std::memcpy(&header_buf[4], bytes.data(), 4);
                    h_len = 10;
                } else {
                    header_buf[3] = static_cast<uint8_t>(AddressType::IPV6);
                    auto bytes = sender_ep.address().to_v6().to_bytes();
                    std::memcpy(&header_buf[4], bytes.data(), 16);
                    h_len = 22;
                }

                uint16_t port = sender_ep.port();
                header_buf[h_len - 2] = static_cast<uint8_t>((port >> 8) & 0xFF);
                header_buf[h_len - 1] = static_cast<uint8_t>(port & 0xFF);

                std::array<asio::const_buffer, 2> buffers = {asio::buffer(header_buf, h_len),
                                                             asio::buffer(buffer.data(), n)};

                co_await udp_socket.async_send_to(buffers, last_client_ep, asio::as_tuple(asio::use_awaitable));
            }
        }
    } catch (...) {
    }
}

} // namespace socks5
