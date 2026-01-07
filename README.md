# socks5-cpp

A high-performance, asynchronous SOCKS5 proxy server and client library written in **Modern C++23**.

This project demonstrates how to build efficient, scalable network applications using C++23 coroutines (`co_await`), Asio, and "Zig-style" zero-cost error handling (`std::expected`, `asio::as_tuple`).

## Features

*   **⚡ High Performance:**
    *   **TCP:** **~9.3 Gbps** throughput on localhost.
    *   **UDP:** **~4.0 Gbps** throughput with header optimization and caching.
    *   Uses exception-free control flow in the hot data path.
*   **🛡️ RFC 1928 Compliant:**
    *   **CONNECT:** Full TCP stream support.
    *   **UDP_ASSOCIATE:** Full UDP relay support with packet encapsulation.
    *   Strict version negotiation and authentication selection.
*   **🔒 Secure Defaults:**
    *   Explicit timeouts for handshakes (10s) and idle connections (5m).
    *   Bind-to-address support (e.g., bind only to `127.0.0.1` for local usage).
    *   Strict source validation for UDP associations.
    *   **Safety First:** Compiled with `-Werror` and strict warning flags.
*   **🧵 Asynchronous:** Powered by `asio` (standalone) and C++20/23 coroutines for readable, non-blocking code.
*   **📦 Zero-Dependency Setup:** Uses zig package manager to manage dependencies (Asio, GoogleTest) automatically.

## Requirements

*   **Compiler:** zig c++.

## Building

### Standard (GCC/Clang)

```bash
# Release (Optimized)
zig build --release=fast

# Debug (Sanitizers)
zig build
```

## Usage

### Running the Server

Start the server on port `1080`. By default, it binds to `0.0.0.0` (all interfaces).

```bash
zig build server -- 1080
```

Bind to a specific interface (e.g., localhost only):

```bash
zig build server 1080 127.0.0.1
```

### Using the Client Library

The project includes a header-only-style client library in `include/socks5/client.hpp`.

```cpp
#include "socks5/client.hpp"

// Inside an asio::awaitable<void> coroutine:
asio::ip::tcp::socket socket(io_context);

// Connect to target (google.com:80) via proxy (127.0.0.1:1080)
co_await socks5::Client::connect(
    socket,
    {asio::ip::make_address("127.0.0.1"), 1080}, 
    "google.com", 80
);

// 'socket' is now effectively connected to google.com.
// Read/Write as normal.
```

## Testing & Benchmarking

**Run Unit & Compliance Tests:**
Verifies RFC compliance (handshake, errors, address types, UDP associate) and integration.

**Important:** It is recommended to run tests in both Debug (for safety) and Release (for correctness under optimization) modes.

```bash
zig build test
```

**Run Throughput Benchmark:**
Spawns 100 concurrent clients pushing data through the proxy.

**Note:** Always compile in **Release** mode for benchmarks!

```bash
# TCP Benchmark
zig build benchmark -- tcp

# UDP Benchmark
zig build benchmark -- udp
```

## Implementation Details

*   **Zig-Style Error Handling:** The server avoids `try/catch` in the relay loop. It uses `asio::as_tuple` to receive `(std::error_code, size_t)` pairs directly from `co_await`, minimizing runtime overhead for common network events like disconnects.
*   **Optimized UDP Relay:**
    *   **Zero-Allocation:** Reply headers are constructed on the stack.
    *   **Resolution Caching:** Destination DNS resolution is cached per flow to avoid high-latency lookups for streaming traffic.
*   **Coroutines:** Extensive use of `asio::awaitable<T>` allows linear code flow for asynchronous operations.
*   **Timeouts:** Custom `with_timeout_nothrow` wrapper ensures no operation hangs indefinitely, returning `std::expected` to the caller.

## License

MIT
