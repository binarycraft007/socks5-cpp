#include "socks5/protocol.hpp"

namespace socks5 {

class Socks5Category : public std::error_category {
  public:
    const char* name() const noexcept override { return "socks5"; }

    std::string message(int ev) const override {
        switch (static_cast<Error>(ev)) {
            case Error::SUCCESS:
                return "Success";
            case Error::INVALID_VERSION:
                return "Invalid SOCKS version";
            case Error::NO_ACCEPTABLE_AUTH:
                return "No acceptable authentication method";
            case Error::AUTH_FAILED:
                return "Authentication failed";
            case Error::UNSUPPORTED_COMMAND:
                return "Unsupported command";
            case Error::UNSUPPORTED_ADDRESS_TYPE:
                return "Unsupported address type";
            case Error::INVALID_FORMAT:
                return "Invalid message format";
            case Error::CONNECTION_FAILED:
                return "Target connection failed";
            default:
                return "Unknown error";
        }
    }
};

const Socks5Category& socks5_category() {
    static Socks5Category instance;
    return instance;
}

std::error_code make_error_code(Error e) {
    return {static_cast<int>(e), socks5_category()};
}

} // namespace socks5
