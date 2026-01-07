#include "socks5/server.hpp"

#include <print>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::println(stderr, "Usage: socks5_server <port> [bind_ip]");
        return 1;
    }

    uint16_t port = static_cast<uint16_t>(std::stoi(argv[1]));
    std::string ip = (argc == 3) ? argv[2] : "0.0.0.0";

    try {
        asio::io_context io_context(1); // One thread for now, or hardware_concurrency

        socks5::Server server(io_context, port, ip);
        server.start();

        std::println("SOCKS5 Server listening on {}:{}...", ip, port);

        // Signal handling
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto) { io_context.stop(); });

        io_context.run();
    } catch (std::exception& e) {
        std::println(stderr, "Exception: {}", e.what());
    }

    return 0;
}