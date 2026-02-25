/// @file PcapIngester.cpp
/// @brief PCAP file reading and writing implementation.
/// @author Bibek Thakur

#include "sentinel/capture/PcapIngester.hpp"
#include <cstring>
#include <iostream>

namespace sentinel {

// ═══════════════════════════════════════════════════════════════════════════
// PcapIngester
// ═══════════════════════════════════════════════════════════════════════════

bool PcapIngester::open(const std::string &path) {
  file_.open(path, std::ios::binary);
  if (!file_.is_open()) {
    std::cerr << "[PcapIngester] Failed to open: " << path << "\n";
    return false;
  }

  file_.read(reinterpret_cast<char *>(&header_), sizeof(header_));
  if (!file_.good()) {
    std::cerr << "[PcapIngester] Failed to read global header\n";
    return false;
  }

  // Detect endianness
  if (header_.magic_number == 0xA1B2C3D4) {
    needs_swap_ = false;
  } else if (header_.magic_number == 0xD4C3B2A1) {
    needs_swap_ = true;
    header_.version_major = swap16(header_.version_major);
    header_.version_minor = swap16(header_.version_minor);
    header_.snaplen = swap32(header_.snaplen);
    header_.network = swap32(header_.network);
  } else {
    std::cerr << "[PcapIngester] Invalid magic number: 0x" << std::hex
              << header_.magic_number << "\n";
    return false;
  }

  return true;
}

void PcapIngester::close() {
  if (file_.is_open())
    file_.close();
}

std::optional<RawFrame> PcapIngester::nextFrame() {
  PcapPacketHeader pkt_hdr{};
  file_.read(reinterpret_cast<char *>(&pkt_hdr), sizeof(pkt_hdr));
  if (!file_.good())
    return std::nullopt;

  if (needs_swap_) {
    pkt_hdr.ts_sec = swap32(pkt_hdr.ts_sec);
    pkt_hdr.ts_usec = swap32(pkt_hdr.ts_usec);
    pkt_hdr.incl_len = swap32(pkt_hdr.incl_len);
    pkt_hdr.orig_len = swap32(pkt_hdr.orig_len);
  }

  // Sanity check
  if (pkt_hdr.incl_len > header_.snaplen || pkt_hdr.incl_len > 65535) {
    std::cerr << "[PcapIngester] Invalid packet length: " << pkt_hdr.incl_len
              << "\n";
    return std::nullopt;
  }

  RawFrame frame;
  frame.header = pkt_hdr;
  frame.data.resize(pkt_hdr.incl_len);
  file_.read(reinterpret_cast<char *>(frame.data.data()), pkt_hdr.incl_len);
  if (!file_.good() && !file_.eof())
    return std::nullopt;

  return frame;
}

std::size_t
PcapIngester::forEachFrame(std::function<void(const RawFrame &)> callback) {
  std::size_t count = 0;
  while (auto frame = nextFrame()) {
    callback(*frame);
    ++count;
  }
  return count;
}

uint16_t PcapIngester::swap16(uint16_t v) noexcept {
  return (v >> 8) | (v << 8);
}

uint32_t PcapIngester::swap32(uint32_t v) noexcept {
  return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) |
         ((v << 24) & 0xFF000000);
}

// ═══════════════════════════════════════════════════════════════════════════
// PcapWriter
// ═══════════════════════════════════════════════════════════════════════════

bool PcapWriter::open(const std::string &path) {
  file_.open(path, std::ios::binary | std::ios::trunc);
  return file_.is_open();
}

bool PcapWriter::writeGlobalHeader(const PcapGlobalHeader &hdr) {
  file_.write(reinterpret_cast<const char *>(&hdr), sizeof(hdr));
  return file_.good();
}

bool PcapWriter::writePacket(const PcapPacketHeader &pkt_hdr,
                             const uint8_t *data, std::size_t len) {
  file_.write(reinterpret_cast<const char *>(&pkt_hdr), sizeof(pkt_hdr));
  file_.write(reinterpret_cast<const char *>(data),
              static_cast<std::streamsize>(len));
  return file_.good();
}

bool PcapWriter::writePacket(const PacketEnvelope &env) {
  PcapPacketHeader hdr{};
  hdr.ts_sec = env.ts_sec;
  hdr.ts_usec = env.ts_usec;
  hdr.incl_len = static_cast<uint32_t>(env.raw_data.size());
  hdr.orig_len = hdr.incl_len;
  return writePacket(hdr, env.raw_data.data(), env.raw_data.size());
}

void PcapWriter::close() {
  if (file_.is_open())
    file_.close();
}

} // namespace sentinel
