#pragma once

#include "asio_config.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

namespace socks5 {

constexpr uint8_t VERSION = 0x05;
constexpr uint8_t RSV = 0x00;

enum class AuthMethod : uint8_t {
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    USER_PASS = 0x02,
    NO_ACCEPTABLE = 0xFF
};

enum class Command : uint8_t {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

enum class AddressType : uint8_t {
    IPV4 = 0x01,
    DOMAIN_NAME = 0x03,
    IPV6 = 0x04
};

enum class Reply : uint8_t {
    SUCCEEDED = 0x00,
    GENERIC_FAILURE = 0x01,
    CONNECTION_NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
};

// Error category for SOCKS5
enum class Error {
    SUCCESS = 0,
    INVALID_VERSION,
    NO_ACCEPTABLE_AUTH,
    AUTH_FAILED,
    UNSUPPORTED_COMMAND,
    UNSUPPORTED_ADDRESS_TYPE,
    INVALID_FORMAT,
    CONNECTION_FAILED
};

std::error_code make_error_code(Error e);

// Helpers to read/write specific SOCKS5 structures asynchronously

// Handshake: Client sends supported methods
struct HandshakeRequest {
    std::vector<AuthMethod> methods;
};

// Handshake: Server selects method
struct HandshakeResponse {
    AuthMethod method;
};

// Request: Client asks to connect/bind
struct Request {
    Command command;
    AddressType address_type;
    std::string domain;   // Used if address_type == DOMAIN
    asio::ip::address ip; // Used if address_type == IPV4 or IPV6
    uint16_t port;
};

// Reply: Server responds to Request
struct Response {
    Reply reply;
    AddressType address_type;
    std::string domain;
    asio::ip::address ip;
    uint16_t port;
};

} // namespace socks5

namespace std {
template <>
struct is_error_code_enum<socks5::Error> : true_type {};
} // namespace std
