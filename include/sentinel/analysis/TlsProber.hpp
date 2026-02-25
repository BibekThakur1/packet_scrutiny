/// @file TlsProber.hpp
/// @brief Extracts Server Name Indication (SNI) from TLS ClientHello messages.
/// @author Bibek Thakur

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// TlsProber — Inspects TCP payload for a TLS ClientHello and extracts the SNI
//
// The SNI is the hostname the client wishes to connect to, sent in cleartext
// during the TLS handshake.  This is the primary signal used by the
// AppFingerprinter to classify HTTPS flows.
// ─────────────────────────────────────────────────────────────────────────────
class TlsProber {
public:
  /// Attempt to extract the SNI from a TCP payload.
  /// Returns std::nullopt if the payload is not a valid TLS ClientHello
  /// or does not contain an SNI extension.
  [[nodiscard]] static std::optional<std::string>
  extractSNI(const uint8_t *payload, std::size_t length) noexcept;

private:
  // TLS record / handshake constants
  static constexpr uint8_t kContentTypeHandshake = 0x16;
  static constexpr uint8_t kHandshakeClientHello = 0x01;
  static constexpr uint16_t kExtensionSNI = 0x0000;
  static constexpr uint8_t kSNIHostName = 0x00;
};

} // namespace sentinel
