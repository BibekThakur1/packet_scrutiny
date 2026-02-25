/// @file Types.cpp
/// @brief Implementation of core type utilities.
/// @author Bibek Thakur

#include "sentinel/core/Types.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// FlowKey
// ─────────────────────────────────────────────────────────────────────────────
std::string FlowKey::toString() const {
  return ipToString(src_ip) + ":" + std::to_string(src_port) + " → " +
         ipToString(dst_ip) + ":" + std::to_string(dst_port) + " (" +
         std::string(protocolNumberToName(protocol)) + ")";
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowPhase / Verdict name helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string_view flowPhaseToName(FlowPhase phase) noexcept {
  switch (phase) {
  case FlowPhase::Initiated:
    return "Initiated";
  case FlowPhase::Handshake:
    return "Handshake";
  case FlowPhase::Active:
    return "Active";
  case FlowPhase::Classified:
    return "Classified";
  case FlowPhase::Terminated:
    return "Terminated";
  }
  return "Unknown";
}

std::string_view verdictToName(Verdict v) noexcept {
  switch (v) {
  case Verdict::Forward:
    return "Forward";
  case Verdict::Drop:
    return "Drop";
  case Verdict::Inspect:
    return "Inspect";
  case Verdict::LogOnly:
    return "LogOnly";
  }
  return "Unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineMetrics
// ─────────────────────────────────────────────────────────────────────────────
std::string EngineMetrics::toReport() const {
  std::ostringstream os;
  os << "╔══════════════════════════════════════════╗\n"
     << "║      PacketScrutiny Engine Report        ║\n"
     << "╠══════════════════════════════════════════╣\n"
     << "║  Total Packets      : " << std::setw(17) << total_packets << " ║\n"
     << "║  Total Bytes        : " << std::setw(17) << total_bytes << " ║\n"
     << "║  Forwarded          : " << std::setw(17) << forwarded_packets
     << " ║\n"
     << "║  Dropped            : " << std::setw(17) << dropped_packets << " ║\n"
     << "║  TCP Packets        : " << std::setw(17) << tcp_packets << " ║\n"
     << "║  UDP Packets        : " << std::setw(17) << udp_packets << " ║\n"
     << "║  Other Packets      : " << std::setw(17) << other_packets << " ║\n"
     << "║  Active Connections : " << std::setw(17) << active_connections
     << " ║\n"
     << "╚══════════════════════════════════════════╝\n";
  return os.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// IP / MAC helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string ipToString(uint32_t ip) {
  char buf[INET_ADDRSTRLEN];
  // ip is stored in host byte order internally; convert to network order for
  // inet_ntop
  uint32_t net = htonl(ip);
  inet_ntop(AF_INET, &net, buf, sizeof(buf));
  return std::string(buf);
}

uint32_t stringToIp(const std::string &s) {
  struct in_addr addr {};
  if (inet_pton(AF_INET, s.c_str(), &addr) != 1) {
    return 0;
  }
  return ntohl(addr.s_addr);
}

std::string macToString(const uint8_t *mac) {
  char buf[18];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

} // namespace sentinel
