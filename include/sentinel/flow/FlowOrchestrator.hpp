/// @file FlowOrchestrator.hpp
/// @brief Aggregates statistics across all SessionLedger instances.
/// @author Bibek Thakur

#pragma once

#include "sentinel/flow/SessionLedger.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// FlowOrchestrator — Global view across all per-thread SessionLedgers
// ─────────────────────────────────────────────────────────────────────────────
class FlowOrchestrator {
public:
  explicit FlowOrchestrator(std::size_t num_ledgers = 1);

  /// Register a ledger (call once per processing thread).
  void registerLedger(int id, SessionLedger *ledger);

  /// Aggregated statistics across all ledgers.
  struct GlobalStats {
    std::size_t total_active = 0;
    std::size_t total_seen = 0;
    std::unordered_map<AppSignature, std::size_t> app_distribution;
    std::vector<std::pair<std::string, std::size_t>> top_domains;
  };

  [[nodiscard]] GlobalStats aggregate() const;

  /// Generate a formatted report string.
  [[nodiscard]] std::string generateReport() const;

private:
  std::vector<SessionLedger *> ledgers_;
  mutable std::mutex mutex_;
};

} // namespace sentinel
