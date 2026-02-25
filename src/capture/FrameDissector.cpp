/// @file FrameDissector.cpp
/// @brief Multi-layer packet dissection: Ethernet → IPv4 → TCP/UDP.
/// @author Bibek Thakur

#include "sentinel/capture/FrameDissector.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

bool FrameDissector::dissect(const RawFrame &frame, DissectedFrame &out) {
  out = {}; // reset
  out.ts_sec = frame.header.ts_sec;
  out.ts_usec = frame.header.ts_usec;

  const uint8_t *data = frame.data.data();
  std::size_t len = frame.data.size();
  std::size_t offset = 0;

  if (!parseEthernet(data, len, out, offset))
    return false;

  if (out.ether_type == ether_type::kIPv4 && out.has_ip == false) {
    if (!parseIPv4(data, len, out, offset))
      return false;
  }

  if (out.has_ip) {
    if (out.protocol == ip_proto::kTCP) {
      parseTCP(data, len, out, offset);
    } else if (out.protocol == ip_proto::kUDP) {
      parseUDP(data, len, out, offset);
    }
  }

  return true;
}

PacketEnvelope FrameDissector::toEnvelope(const RawFrame &frame,
                                          const DissectedFrame &d,
                                          uint32_t packet_id) {
  PacketEnvelope env;
  env.id = packet_id;
  env.raw_data = frame.data; // copy
  env.ts_sec = d.ts_sec;
  env.ts_usec = d.ts_usec;

  if (d.has_ip) {
    env.key.src_ip = d.src_ip_raw;
    env.key.dst_ip = d.dst_ip_raw;
    env.key.protocol = d.protocol;
  }
  if (d.has_tcp || d.has_udp) {
    env.key.src_port = d.src_port;
    env.key.dst_port = d.dst_port;
  }
  env.tcp_flags = d.tcp_flags;
  env.payload_offset = d.payload_offset;
  env.payload_length = d.payload_length;

  return env;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ethernet
// ─────────────────────────────────────────────────────────────────────────────

bool FrameDissector::parseEthernet(const uint8_t *data, std::size_t len,
                                   DissectedFrame &out, std::size_t &offset) {
  constexpr std::size_t kEthHdrLen = 14;
  if (len < kEthHdrLen)
    return false;

  out.dst_mac = macToString(data);
  out.src_mac = macToString(data + 6);

  uint16_t etype;
  std::memcpy(&etype, data + 12, 2);
  out.ether_type = ntohs(etype);

  offset = kEthHdrLen;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv4
// ─────────────────────────────────────────────────────────────────────────────

bool FrameDissector::parseIPv4(const uint8_t *data, std::size_t len,
                               DissectedFrame &out, std::size_t &offset) {
  if (offset + 20 > len)
    return false; // Minimum IPv4 header

  const uint8_t *ip = data + offset;

  uint8_t version_ihl = ip[0];
  uint8_t version = (version_ihl >> 4) & 0x0F;
  uint8_t ihl = version_ihl & 0x0F;

  if (version != 4)
    return false;

  std::size_t ip_hdr_len = static_cast<std::size_t>(ihl) * 4;
  if (offset + ip_hdr_len > len)
    return false;

  out.has_ip = true;
  out.ip_version = 4;
  out.ttl = ip[8];
  out.protocol = ip[9];

  uint32_t src_raw, dst_raw;
  std::memcpy(&src_raw, ip + 12, 4);
  std::memcpy(&dst_raw, ip + 16, 4);

  out.src_ip_raw = ntohl(src_raw);
  out.dst_ip_raw = ntohl(dst_raw);
  out.src_ip = ipToString(out.src_ip_raw);
  out.dst_ip = ipToString(out.dst_ip_raw);

  offset += ip_hdr_len;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP
// ─────────────────────────────────────────────────────────────────────────────

bool FrameDissector::parseTCP(const uint8_t *data, std::size_t len,
                              DissectedFrame &out, std::size_t &offset) {
  if (offset + 20 > len)
    return false; // Minimum TCP header

  const uint8_t *tcp = data + offset;

  uint16_t sp, dp;
  std::memcpy(&sp, tcp, 2);
  std::memcpy(&dp, tcp + 2, 2);
  out.src_port = ntohs(sp);
  out.dst_port = ntohs(dp);

  uint32_t seq, ack;
  std::memcpy(&seq, tcp + 4, 4);
  std::memcpy(&ack, tcp + 8, 4);
  out.seq_number = ntohl(seq);
  out.ack_number = ntohl(ack);

  uint8_t data_offset_byte = tcp[12];
  std::size_t tcp_hdr_len =
      static_cast<std::size_t>((data_offset_byte >> 4) & 0x0F) * 4;
  out.tcp_flags = tcp[13];

  out.has_tcp = true;

  offset += tcp_hdr_len;
  if (offset < len) {
    out.payload_offset = offset;
    out.payload_length = len - offset;
    out.payload_ptr = data + offset;
  }

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP
// ─────────────────────────────────────────────────────────────────────────────

bool FrameDissector::parseUDP(const uint8_t *data, std::size_t len,
                              DissectedFrame &out, std::size_t &offset) {
  if (offset + 8 > len)
    return false;

  const uint8_t *udp = data + offset;

  uint16_t sp, dp;
  std::memcpy(&sp, udp, 2);
  std::memcpy(&dp, udp + 2, 2);
  out.src_port = ntohs(sp);
  out.dst_port = ntohs(dp);

  out.has_udp = true;
  offset += 8;

  if (offset < len) {
    out.payload_offset = offset;
    out.payload_length = len - offset;
    out.payload_ptr = data + offset;
  }

  return true;
}

} // namespace sentinel
