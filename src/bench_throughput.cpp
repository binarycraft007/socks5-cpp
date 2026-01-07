#include "asio_config.hpp"
#include "socks5/client.hpp"
#include "socks5/server.hpp"

#include <asio/experimental/awaitable_operators.hpp>
#include <atomic>
#include <chrono>
#include <cstring>
#include <print>
#include <thread>
#include <vector>

using namespace asio::experimental::awaitable_operators;

// Configuration
constexpr uint16_t PROXY_PORT = 10801;
constexpr uint16_t DISCARD_PORT_TCP = 10802;
constexpr uint16_t DISCARD_PORT_UDP = 10803;
constexpr size_t NUM_CLIENTS = 100;
constexpr size_t DATA_PER_CLIENT = 10 * 1024 * 1024; // 10 MB
constexpr size_t BUFFER_SIZE = 32 * 1024;            // 32KB

// TCP Discard
asio::awaitable<void> discard_tcp_session(asio::ip::tcp::socket socket) {
    char data[BUFFER_SIZE];
    try {
        while (true) {
            co_await socket.async_read_some(asio::buffer(data), asio::use_awaitable);
        }
    } catch (...) {
    }
}

asio::awaitable<void> run_discard_tcp(asio::io_context& ctx) {
    asio::ip::tcp::acceptor acceptor(ctx, {asio::ip::tcp::v4(), DISCARD_PORT_TCP});
    try {
        while (true) {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            asio::co_spawn(ctx, discard_tcp_session(std::move(socket)), asio::detached);
        }
    } catch (...) {
    }
}

// UDP Discard (Receiver)
asio::awaitable<void> run_discard_udp(asio::io_context& ctx) {
    asio::ip::udp::socket socket(ctx, {asio::ip::udp::v4(), DISCARD_PORT_UDP});
    char data[65536];
    asio::ip::udp::endpoint sender;
    try {
        while (true) {
            co_await socket.async_receive_from(asio::buffer(data), sender, asio::use_awaitable);
        }
    } catch (...) {
    }
}

// TCP Client
asio::awaitable<void> client_tcp(asio::io_context& ctx, const std::vector<char>& shared_payload) {
    asio::ip::tcp::socket socket(ctx);
    try {
        co_await socks5::Client::connect(socket, {asio::ip::make_address("127.0.0.1"), PROXY_PORT}, "127.0.0.1",
                                         DISCARD_PORT_TCP);

        size_t remaining = DATA_PER_CLIENT;
        while (remaining > 0) {
            size_t chunk = std::min(remaining, shared_payload.size());
            co_await asio::async_write(socket, asio::buffer(shared_payload.data(), chunk), asio::use_awaitable);
            remaining -= chunk;
        }
        socket.close();
    } catch (...) {
    }
}

// UDP Client
asio::awaitable<void> client_udp(asio::io_context& ctx, const std::vector<char>& shared_payload) {
    asio::ip::tcp::socket ctrl_socket(ctx);
    asio::ip::udp::socket udp_socket(ctx, {asio::ip::udp::v4(), 0});

    try {
        // 1. Handshake TCP
        co_await ctrl_socket.async_connect({asio::ip::make_address("127.0.0.1"), PROXY_PORT}, asio::use_awaitable);

        // Handshake
        uint8_t handshake[] = {0x05, 0x01, 0x00};
        co_await asio::async_write(ctrl_socket, asio::buffer(handshake), asio::use_awaitable);
        uint8_t h_resp[2];
        co_await asio::async_read(ctrl_socket, asio::buffer(h_resp), asio::use_awaitable);

        // UDP Associate
        std::vector<uint8_t> req = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(ctrl_socket, asio::buffer(req), asio::use_awaitable);

        uint8_t resp[10];
        co_await asio::async_read(ctrl_socket, asio::buffer(resp), asio::use_awaitable);
        uint16_t relay_port = (resp[8] << 8) | resp[9];
        asio::ip::udp::endpoint relay_ep(asio::ip::make_address("127.0.0.1"), relay_port);

        // 2. Blast UDP
        // Header: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
        // Pre-build header for performance
        std::vector<uint8_t> packet;
        packet.reserve(10 + shared_payload.size());
        packet.push_back(0);
        packet.push_back(0);
        packet.push_back(0);    // RSV+FRAG
        packet.push_back(0x01); // IPv4
        packet.push_back(127);
        packet.push_back(0);
        packet.push_back(0);
        packet.push_back(1); // 127.0.0.1
        packet.push_back((DISCARD_PORT_UDP >> 8) & 0xFF);
        packet.push_back(DISCARD_PORT_UDP & 0xFF);

        size_t remaining = DATA_PER_CLIENT;
        // Limit UDP packet size to MTU-safe or reasonable (e.g. 1400)
        // Note: DATA_PER_CLIENT is 10MB. We need loop.
        size_t chunk_size = 1400; // Typical MTU

        while (remaining > 0) {
            size_t current_chunk = std::min(remaining, chunk_size);

            // Scatter/Gather: Header + Payload Slice
            std::vector<asio::const_buffer> buffers;
            buffers.push_back(asio::buffer(packet));
            buffers.push_back(asio::buffer(shared_payload.data(), current_chunk));

            co_await udp_socket.async_send_to(buffers, relay_ep, asio::use_awaitable);

            remaining -= current_chunk;
        }

    } catch (...) {
    }
}

int main(int argc, char* argv[]) {
    std::string mode = "tcp";
    if (argc > 1)
        mode = argv[1];

    asio::io_context ctx(std::thread::hardware_concurrency());

    // Start Servers
    socks5::Server proxy(ctx, PROXY_PORT, "127.0.0.1");
    proxy.start();
    asio::co_spawn(ctx, run_discard_tcp(ctx), asio::detached);
    asio::co_spawn(ctx, run_discard_udp(ctx), asio::detached);

    // Payload
    std::vector<char> payload(BUFFER_SIZE);
    for (size_t i = 0; i < BUFFER_SIZE; ++i)
        payload[i] = static_cast<char>(i % 255);

    std::println("Benchmark Configuration:");
    std::println("  Mode: {}", mode);
    std::println("  Clients: {}", NUM_CLIENTS);
    std::println("  Data/Client: {} MB", DATA_PER_CLIENT / 1024 / 1024);
    std::println("Starting benchmark...");

    std::atomic<size_t> active_clients = NUM_CLIENTS;
    auto start = std::chrono::steady_clock::now();

    for (size_t i = 0; i < NUM_CLIENTS; ++i) {
        asio::co_spawn(
            ctx,
            [&, i]() -> asio::awaitable<void> {
                if (mode == "udp")
                    co_await client_udp(ctx, payload);
                else
                    co_await client_tcp(ctx, payload);
                active_clients--;
            },
            asio::detached);
    }

    std::vector<std::thread> threads;
    for (size_t i = 0; i < std::thread::hardware_concurrency(); ++i) {
        threads.emplace_back([&ctx] { ctx.run(); });
    }

    while (active_clients > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = end - start;

    ctx.stop();
    for (auto& t : threads)
        t.join();

    double total_bytes = static_cast<double>(NUM_CLIENTS * DATA_PER_CLIENT);
    double mb = total_bytes / (1024 * 1024);
    double mbs = mb / diff.count();
    double gbps = (total_bytes * 8) / (1000 * 1000 * 1000) / diff.count();

    std::println("Benchmark Complete:");
    std::println("  Time: {:.2f} s", diff.count());
    std::println("  Throughput: {:.2f} MB/s", mbs);
    std::println("  Bandwidth: {:.2f} Gbps", gbps);

    return 0;
}
