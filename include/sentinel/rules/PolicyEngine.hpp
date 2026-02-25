/// @file PolicyEngine.hpp
/// @brief JSON-configurable rule engine for blocking IPs, apps, domains, and
/// ports.
/// @author Bibek Thakur

#pragma once

#include "sentinel/core/Types.hpp"
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// BlockReason — Explains why a packet was blocked
// ─────────────────────────────────────────────────────────────────────────────
struct BlockReason {
  enum class Kind { IP, App, Domain, Port };
  Kind kind;
  std::string detail; ///< Human-readable explanation
};

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngine — Manages blocking / filtering rules
//
// Rules are loaded from a JSON file and can be modified at runtime.
// All public methods are thread-safe (read-write lock internally).
// ─────────────────────────────────────────────────────────────────────────────
class PolicyEngine {
public:
  PolicyEngine() = default;

  // ── IP Blocking ─────────────────────────────────────────────────────
  void blockIP(const std::string &ip);
  void blockIP(uint32_t ip);
  void unblockIP(const std::string &ip);
  void unblockIP(uint32_t ip);
  [[nodiscard]] bool isIPBlocked(uint32_t ip) const;
  [[nodiscard]] std::vector<std::string> blockedIPs() const;

  // ── Application Blocking ────────────────────────────────────────────
  void blockApp(AppSignature app);
  void unblockApp(AppSignature app);
  [[nodiscard]] bool isAppBlocked(AppSignature app) const;
  [[nodiscard]] std::vector<AppSignature> blockedApps() const;

  // ── Domain Blocking (supports *.example.com wildcards) ──────────────
  void blockDomain(const std::string &domain);
  void unblockDomain(const std::string &domain);
  [[nodiscard]] bool isDomainBlocked(const std::string &domain) const;
  [[nodiscard]] std::vector<std::string> blockedDomains() const;

  // ── Port Blocking ───────────────────────────────────────────────────
  void blockPort(uint16_t port);
  void unblockPort(uint16_t port);
  [[nodiscard]] bool isPortBlocked(uint16_t port) const;

  // ── Combined Evaluation ─────────────────────────────────────────────
  /// Evaluate all rules against a packet's metadata.
  /// Returns a BlockReason if the packet should be dropped, std::nullopt
  /// otherwise.
  [[nodiscard]] std::optional<BlockReason>
  evaluate(uint32_t src_ip, uint16_t dst_port, AppSignature app,
           const std::string &domain) const;

  // ── Persistence (JSON) ──────────────────────────────────────────────
  /// Load rules from a JSON file, merging with any existing rules.
  [[nodiscard]] bool loadFromJSON(const std::string &path);

  /// Save the current rule set to a JSON file.
  [[nodiscard]] bool saveToJSON(const std::string &path) const;

  /// Remove all rules.
  void clearAll();

  // ── Statistics ──────────────────────────────────────────────────────
  struct RuleStats {
    std::size_t ip_count = 0;
    std::size_t app_count = 0;
    std::size_t domain_count = 0;
    std::size_t port_count = 0;
  };
  [[nodiscard]] RuleStats ruleStats() const;

private:
  mutable std::mutex mutex_;

  std::unordered_set<uint32_t> blocked_ips_;
  std::unordered_set<AppSignature> blocked_apps_;
  std::unordered_set<std::string> blocked_domains_;
  std::vector<std::string> domain_patterns_; ///< Wildcard entries
  std::unordered_set<uint16_t> blocked_ports_;

  /// Check whether `domain` matches a wildcard `pattern` (e.g. *.fb.com).
  [[nodiscard]] static bool matchWildcard(const std::string &domain,
                                          const std::string &pattern);
};

} // namespace sentinel
