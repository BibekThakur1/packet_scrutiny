/// @file TlsProber.cpp
/// @brief TLS ClientHello SNI extraction.
/// @author Bibek Thakur

#include "sentinel/analysis/TlsProber.hpp"
#include <cstring>

namespace sentinel {

std::optional<std::string> TlsProber::extractSNI(const uint8_t *payload,
                                                 std::size_t length) noexcept {
  // Minimum sizes: TLS record header (5) + Handshake header (4) +
  // ClientHello = ~43 bytes minimum
  if (!payload || length < 43)
    return std::nullopt;

  // ── TLS Record Layer ──
  // Byte 0: content type (must be 0x16 – Handshake)
  if (payload[0] != kContentTypeHandshake)
    return std::nullopt;

  // Bytes 1-2: TLS version (we accept any)
  // Bytes 3-4: record length
  uint16_t record_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
  if (5u + record_len > length)
    return std::nullopt;

  // ── Handshake Layer ──
  std::size_t pos = 5;
  if (payload[pos] != kHandshakeClientHello)
    return std::nullopt;

  // Handshake length (3 bytes)
  // uint32_t hs_len = (payload[pos+1] << 16) | (payload[pos+2] << 8) |
  // payload[pos+3];
  pos += 4;

  // Skip: client version (2), random (32)
  pos += 2 + 32;
  if (pos >= length)
    return std::nullopt;

  // Skip: session ID
  uint8_t session_id_len = payload[pos];
  pos += 1 + session_id_len;
  if (pos + 2 > length)
    return std::nullopt;

  // Skip: cipher suites
  uint16_t cipher_suites_len =
      (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
  pos += 2 + cipher_suites_len;
  if (pos + 1 > length)
    return std::nullopt;

  // Skip: compression methods
  uint8_t comp_len = payload[pos];
  pos += 1 + comp_len;
  if (pos + 2 > length)
    return std::nullopt;

  // ── Extensions ──
  uint16_t extensions_len =
      (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
  pos += 2;

  std::size_t extensions_end = pos + extensions_len;
  if (extensions_end > length)
    extensions_end = length;

  while (pos + 4 <= extensions_end) {
    uint16_t ext_type =
        (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    uint16_t ext_len =
        (static_cast<uint16_t>(payload[pos + 2]) << 8) | payload[pos + 3];
    pos += 4;

    if (ext_type == kExtensionSNI && ext_len > 0) {
      // SNI extension: server_name_list_length (2)
      if (pos + 2 > extensions_end)
        break;
      // uint16_t sni_list_len = ...;
      pos += 2;

      // server_name_type (1 byte) must be 0x00 (host_name)
      if (pos >= extensions_end)
        break;
      uint8_t name_type = payload[pos];
      pos += 1;
      if (name_type != kSNIHostName)
        break;

      // host_name_length (2 bytes)
      if (pos + 2 > extensions_end)
        break;
      uint16_t name_len =
          (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
      pos += 2;

      if (pos + name_len > extensions_end)
        break;
      return std::string(reinterpret_cast<const char *>(payload + pos),
                         name_len);
    }

    pos += ext_len;
  }

  return std::nullopt;
}

} // namespace sentinel
