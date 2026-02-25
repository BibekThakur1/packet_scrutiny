/// @file AppFingerprinter.hpp
/// @brief Maps SNI hostnames to application signatures.
/// @author Bibek Thakur

#pragma once

#include "sentinel/core/Protocol.hpp"
#include <string>
#include <unordered_map>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// AppFingerprinter — Classifies network flows by mapping domain names and
// port numbers to known application signatures.
// ─────────────────────────────────────────────────────────────────────────────
class AppFingerprinter {
public:
  AppFingerprinter();

  /// Classify based on a detected SNI hostname.
  [[nodiscard]] AppSignature classifyBySNI(const std::string &sni) const;

  /// Classify based on destination port (fallback heuristic).
  [[nodiscard]] AppSignature classifyByPort(uint16_t dst_port) const;

  /// Classify using all available signals.
  [[nodiscard]] AppSignature classify(const std::string &sni,
                                      uint16_t dst_port) const;

private:
  /// Mapping from domain suffix → AppSignature
  struct DomainRule {
    std::string suffix;
    AppSignature sig;
  };
  std::vector<DomainRule> domain_rules_;

  /// Port-based fallbacks
  std::unordered_map<uint16_t, AppSignature> port_rules_;

  void loadDefaults();
};

} // namespace sentinel
