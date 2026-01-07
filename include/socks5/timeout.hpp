#pragma once

#include "asio_config.hpp"

#include <asio/experimental/awaitable_operators.hpp>
#include <expected>
#include <system_error>
#include <variant>

namespace socks5 {

using namespace asio::experimental::awaitable_operators;

// Awaitable that returns std::expected<T, std::error_code>
// It takes an awaitable that produces a tuple (std::error_code, T) or just (std::error_code)

// Helper to run an awaitable with a timeout, returning expected<T, error_code>
// T is the success type (e.g. size_t for write/read, or void).
// Op is the awaitable type.
template <typename T = void, typename Op>
auto with_timeout_nothrow(Op&& op, std::chrono::steady_clock::duration duration)
    -> asio::awaitable<std::expected<T, std::error_code>> {
    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(duration);

    // Run operation and timer in parallel
    auto result = co_await (std::forward<Op>(op) || timer.async_wait(asio::as_tuple(asio::use_awaitable)));

    // Result index 0: The operation finished
    if (result.index() == 0) {
        auto& op_result = std::get<0>(result);
        // op_result is tuple<error_code, T...>
        std::error_code ec = std::get<0>(op_result);
        if (ec) {
            co_return std::unexpected(ec);
        }

        if constexpr (!std::is_void_v<T>) {
            co_return std::get<1>(op_result);
        } else {
            co_return T{};
        }
    }

    // Result index 1: The timer finished (Timeout)
    co_return std::unexpected(std::make_error_code(std::errc::timed_out));
}

} // namespace socks5
