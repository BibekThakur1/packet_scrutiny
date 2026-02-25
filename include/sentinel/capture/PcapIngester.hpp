/// @file PcapIngester.hpp
/// @brief Reads packets from PCAP files and writes output PCAP files.
/// @author Bibek Thakur

#pragma once

#include "sentinel/core/Types.hpp"
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// RawFrame — One captured frame as read from a PCAP file
// ─────────────────────────────────────────────────────────────────────────────
struct RawFrame {
  PcapPacketHeader header;
  std::vector<uint8_t> data;
};

// ─────────────────────────────────────────────────────────────────────────────
// PcapIngester — Reads a PCAP file packet-by-packet
// ─────────────────────────────────────────────────────────────────────────────
class PcapIngester {
public:
  /// Open a PCAP file for reading. Returns false on failure.
  [[nodiscard]] bool open(const std::string &path);

  /// Close the currently open file.
  void close();

  /// Read the next frame. Returns std::nullopt at EOF or on error.
  [[nodiscard]] std::optional<RawFrame> nextFrame();

  /// Get the global header (valid after open()).
  [[nodiscard]] const PcapGlobalHeader &globalHeader() const noexcept {
    return header_;
  }

  /// Iterate all frames, calling `callback` for each.
  /// Returns the total number of frames processed.
  std::size_t forEachFrame(std::function<void(const RawFrame &)> callback);

  /// Check whether byte-swapping is needed (big-endian PCAP).
  [[nodiscard]] bool needsSwap() const noexcept { return needs_swap_; }

private:
  std::ifstream file_;
  PcapGlobalHeader header_{};
  bool needs_swap_ = false;

  /// Swap 16/32-bit values when the PCAP was written in the opposite
  /// endianness.
  [[nodiscard]] static uint16_t swap16(uint16_t v) noexcept;
  [[nodiscard]] static uint32_t swap32(uint32_t v) noexcept;
};

// ─────────────────────────────────────────────────────────────────────────────
// PcapWriter — Writes packets to a PCAP output file
// ─────────────────────────────────────────────────────────────────────────────
class PcapWriter {
public:
  /// Create / truncate an output PCAP file. Returns false on failure.
  [[nodiscard]] bool open(const std::string &path);

  /// Write the global header (must be called before any packets).
  bool writeGlobalHeader(const PcapGlobalHeader &hdr);

  /// Write a single packet.
  bool writePacket(const PcapPacketHeader &pkt_hdr, const uint8_t *data,
                   std::size_t len);

  /// Convenience: write from a PacketEnvelope.
  bool writePacket(const PacketEnvelope &env);

  void close();

private:
  std::ofstream file_;
};

} // namespace sentinel
