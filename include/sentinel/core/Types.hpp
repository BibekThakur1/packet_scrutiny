/// @file Types.hpp
/// @brief Core data types used throughout the NetSentinel engine.
/// @author Bibek Thakur
/// @date 2026

#pragma once

#include "Protocol.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// FlowKey — Uniquely identifies a bidirectional network flow (5-tuple)
// ─────────────────────────────────────────────────────────────────────────────
struct FlowKey {
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t protocol = 0; ///< ip_proto::kTCP or ip_proto::kUDP

  [[nodiscard]] bool operator==(const FlowKey &other) const noexcept {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
  }

  /// Create the reverse-direction key for bidirectional matching.
  [[nodiscard]] FlowKey reverse() const noexcept {
    return {dst_ip, src_ip, dst_port, src_port, protocol};
  }

  /// Human-readable representation: "1.2.3.4:80 → 5.6.7.8:443 (TCP)"
  [[nodiscard]] std::string toString() const;
};

/// Hash functor for FlowKey — allows use in unordered containers.
struct FlowKeyHash {
  [[nodiscard]] std::size_t operator()(const FlowKey &key) const noexcept {
    std::size_t h = 0;
    auto combine = [&h](auto val) {
      h ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (h << 6) + (h >> 2);
    };
    combine(key.src_ip);
    combine(key.dst_ip);
    combine(key.src_port);
    combine(key.dst_port);
    combine(key.protocol);
    return h;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// FlowPhase — Lifecycle states of a tracked flow
// ─────────────────────────────────────────────────────────────────────────────
enum class FlowPhase : uint8_t {
  Initiated,  ///< SYN seen (TCP) or first packet (UDP)
  Handshake,  ///< SYN-ACK seen, awaiting completion
  Active,     ///< Connection established, data flowing
  Classified, ///< Application identified
  Terminated  ///< FIN/RST seen or timed out
};

[[nodiscard]] std::string_view flowPhaseToName(FlowPhase phase) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
// Verdict — What should happen to a packet
// ─────────────────────────────────────────────────────────────────────────────
enum class Verdict : uint8_t {
  Forward, ///< Allow the packet through
  Drop,    ///< Block / discard the packet
  Inspect, ///< Needs deeper inspection
  LogOnly  ///< Forward but record for audit
};

[[nodiscard]] std::string_view verdictToName(Verdict v) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
// SessionRecord — Per-flow state stored in the SessionLedger
// ─────────────────────────────────────────────────────────────────────────────
struct SessionRecord {
  FlowKey key;
  FlowPhase phase = FlowPhase::Initiated;
  AppSignature app = AppSignature::Unknown;
  std::string sni; ///< Server Name Indication (if detected)
  Verdict verdict = Verdict::Forward;

  // Traffic counters
  uint64_t packets_in = 0;
  uint64_t packets_out = 0;
  uint64_t bytes_in = 0;
  uint64_t bytes_out = 0;

  // Timestamps
  std::chrono::steady_clock::time_point first_seen;
  std::chrono::steady_clock::time_point last_seen;

  // TCP handshake tracking
  bool syn_seen = false;
  bool syn_ack_seen = false;
  bool fin_seen = false;
};

// ─────────────────────────────────────────────────────────────────────────────
// PacketEnvelope — Wrapper carrying raw packet data through the pipeline
// ─────────────────────────────────────────────────────────────────────────────
struct PacketEnvelope {
  uint32_t id = 0;
  FlowKey key;
  std::vector<uint8_t> raw_data;

  // Byte offsets into raw_data
  std::size_t eth_offset = 0;
  std::size_t ip_offset = 0;
  std::size_t transport_offset = 0;
  std::size_t payload_offset = 0;
  std::size_t payload_length = 0;

  uint8_t tcp_flags = 0;

  // PCAP timestamps
  uint32_t ts_sec = 0;
  uint32_t ts_usec = 0;

  /// Pointer into raw_data at the payload region. May be nullptr.
  [[nodiscard]] const uint8_t *payloadPtr() const noexcept {
    if (payload_length == 0 || payload_offset >= raw_data.size())
      return nullptr;
    return raw_data.data() + payload_offset;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// EngineMetrics — Aggregate statistics for the entire engine
// ─────────────────────────────────────────────────────────────────────────────
struct EngineMetrics {
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t forwarded_packets = 0;
  uint64_t dropped_packets = 0;
  uint64_t tcp_packets = 0;
  uint64_t udp_packets = 0;
  uint64_t other_packets = 0;
  uint64_t active_connections = 0;

  /// Format a multi-line summary report.
  [[nodiscard]] std::string toReport() const;
};

// ─────────────────────────────────────────────────────────────────────────────
// PCAP file structures (for raw I/O)
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)

struct PcapGlobalHeader {
  uint32_t magic_number = 0xA1B2C3D4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  int32_t thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 65535;
  uint32_t network = 1; ///< LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
  uint32_t ts_sec = 0;
  uint32_t ts_usec = 0;
  uint32_t incl_len = 0;
  uint32_t orig_len = 0;
};

#pragma pack(pop)

/// IP address helpers
[[nodiscard]] std::string ipToString(uint32_t ip);
[[nodiscard]] uint32_t stringToIp(const std::string &s);
[[nodiscard]] std::string macToString(const uint8_t *mac);

} // namespace sentinel
