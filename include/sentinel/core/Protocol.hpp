/// @file Protocol.hpp
/// @brief Network protocol constants, enumerations, and flag definitions.
/// @author Bibek Thakur
/// @date 2026

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// EtherType — Link-layer protocol identifiers
// ─────────────────────────────────────────────────────────────────────────────
namespace ether_type {
    inline constexpr uint16_t kIPv4 = 0x0800;
    inline constexpr uint16_t kIPv6 = 0x86DD;
    inline constexpr uint16_t kARP  = 0x0806;
    inline constexpr uint16_t kVLAN = 0x8100;
} // namespace ether_type

// ─────────────────────────────────────────────────────────────────────────────
// IP Protocol Numbers
// ─────────────────────────────────────────────────────────────────────────────
namespace ip_proto {
    inline constexpr uint8_t kICMP = 1;
    inline constexpr uint8_t kTCP  = 6;
    inline constexpr uint8_t kUDP  = 17;
} // namespace ip_proto

// ─────────────────────────────────────────────────────────────────────────────
// TCP Flags — bitmask values
// ─────────────────────────────────────────────────────────────────────────────
namespace tcp_flag {
    inline constexpr uint8_t kFIN = 0x01;
    inline constexpr uint8_t kSYN = 0x02;
    inline constexpr uint8_t kRST = 0x04;
    inline constexpr uint8_t kPSH = 0x08;
    inline constexpr uint8_t kACK = 0x10;
    inline constexpr uint8_t kURG = 0x20;
} // namespace tcp_flag

// ─────────────────────────────────────────────────────────────────────────────
// AppSignature — Application-level classification
// ─────────────────────────────────────────────────────────────────────────────
enum class AppSignature : uint8_t {
    Unknown = 0,
    // Transport protocols
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Well-known services (detected via SNI / heuristics)
    Google,
    Facebook,
    YouTube,
    Twitter,
    Instagram,
    Netflix,
    Amazon,
    Microsoft,
    Apple,
    WhatsApp,
    Telegram,
    TikTok,
    Spotify,
    Zoom,
    Discord,
    GitHub,
    Cloudflare,
    Reddit,
    LinkedIn,
    // Sentinel value — keep last
    COUNT
};

/// Convert an AppSignature to its human-readable name.
[[nodiscard]] std::string_view appSignatureToName(AppSignature sig) noexcept;

/// Map a Server Name Indication string to the best-matching AppSignature.
[[nodiscard]] AppSignature sniToAppSignature(const std::string& sni) noexcept;

/// Convert a TCP flags byte to a human-readable string like "[SYN ACK]".
[[nodiscard]] std::string tcpFlagsToString(uint8_t flags);

/// Convert a protocol number to its name (e.g. 6 → "TCP").
[[nodiscard]] std::string_view protocolNumberToName(uint8_t proto) noexcept;

} // namespace sentinel
