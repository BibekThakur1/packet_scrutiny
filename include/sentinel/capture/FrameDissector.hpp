/// @file FrameDissector.hpp
/// @brief Parses raw Ethernet frames into structured protocol fields.
/// @author Bibek Thakur

#pragma once

#include "sentinel/capture/PcapIngester.hpp"
#include "sentinel/core/Types.hpp"
#include <cstdint>
#include <string>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// DissectedFrame — Result of parsing a raw frame through all protocol layers
// ─────────────────────────────────────────────────────────────────────────────
struct DissectedFrame {
  // Timestamps
  uint32_t ts_sec = 0;
  uint32_t ts_usec = 0;

  // — Ethernet layer —
  std::string src_mac;
  std::string dst_mac;
  uint16_t ether_type = 0;

  // — IP layer —
  bool has_ip = false;
  uint8_t ip_version = 0;
  std::string src_ip;
  std::string dst_ip;
  uint8_t protocol = 0; ///< ip_proto::kTCP, kUDP, etc.
  uint8_t ttl = 0;
  uint32_t src_ip_raw = 0; ///< Network-byte-order raw IP
  uint32_t dst_ip_raw = 0;

  // — Transport layer —
  bool has_tcp = false;
  bool has_udp = false;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;

  // TCP-specific
  uint8_t tcp_flags = 0;
  uint32_t seq_number = 0;
  uint32_t ack_number = 0;

  // Payload
  std::size_t payload_offset = 0; ///< Offset within the raw frame data
  std::size_t payload_length = 0;
  const uint8_t *payload_ptr = nullptr; ///< Points into the raw frame buffer
};

// ─────────────────────────────────────────────────────────────────────────────
// FrameDissector — Stateless dissector for Ethernet/IPv4/TCP/UDP
// ─────────────────────────────────────────────────────────────────────────────
class FrameDissector {
public:
  /// Dissect a raw frame. Returns true on success.
  [[nodiscard]] static bool dissect(const RawFrame &frame, DissectedFrame &out);

  /// Build a PacketEnvelope from a dissected frame + raw data.
  [[nodiscard]] static PacketEnvelope
  toEnvelope(const RawFrame &frame, const DissectedFrame &dissected,
             uint32_t packet_id);

private:
  static bool parseEthernet(const uint8_t *data, std::size_t len,
                            DissectedFrame &out, std::size_t &offset);
  static bool parseIPv4(const uint8_t *data, std::size_t len,
                        DissectedFrame &out, std::size_t &offset);
  static bool parseTCP(const uint8_t *data, std::size_t len,
                       DissectedFrame &out, std::size_t &offset);
  static bool parseUDP(const uint8_t *data, std::size_t len,
                       DissectedFrame &out, std::size_t &offset);
};

} // namespace sentinel
