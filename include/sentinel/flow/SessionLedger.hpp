/// @file SessionLedger.hpp
/// @brief Per-thread flow table that tracks active sessions and their
/// lifecycle.
/// @author Bibek Thakur

#pragma once

#include "sentinel/core/Types.hpp"
#include <chrono>
#include <functional>
#include <unordered_map>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// SessionLedger — Owns and manages SessionRecords for a subset of flows.
//
// Design: Each processing thread holds its own SessionLedger so there is zero
// contention on the flow table.  Flows are consistently hashed to the same
// thread, guaranteeing that the same SessionLedger always handles a given flow.
// ─────────────────────────────────────────────────────────────────────────────
class SessionLedger {
public:
  explicit SessionLedger(int ledger_id, std::size_t capacity = 100'000);

  /// Look up an existing session or create a new one.
  SessionRecord *getOrCreate(const FlowKey &key);

  /// Look up an existing session (returns nullptr if absent).
  SessionRecord *find(const FlowKey &key);

  /// Record a new packet arrival for a session.
  void recordPacket(SessionRecord *rec, std::size_t bytes, bool is_outbound);

  /// Classify the session's application type.
  void classify(SessionRecord *rec, AppSignature app, const std::string &sni);

  /// Mark a session as blocked.
  void block(SessionRecord *rec);

  /// Mark a session as terminated.
  void terminate(const FlowKey &key);

  /// Evict sessions idle for longer than `timeout`. Returns eviction count.
  std::size_t evictStale(std::chrono::seconds timeout = std::chrono::seconds{
                             300});

  /// Number of active sessions.
  [[nodiscard]] std::size_t activeCount() const noexcept {
    return table_.size();
  }

  /// Snapshot of all sessions (for reporting).
  [[nodiscard]] std::vector<SessionRecord> snapshot() const;

  /// Iterate every session.
  void forEach(std::function<void(const SessionRecord &)> visitor) const;

  /// Summary statistics.
  struct Stats {
    std::size_t active = 0;
    std::size_t total_seen = 0;
    std::size_t classified = 0;
    std::size_t blocked = 0;
  };
  [[nodiscard]] Stats stats() const noexcept;

  void clear();

private:
  [[maybe_unused]] int id_;
  std::size_t capacity_;

  std::unordered_map<FlowKey, SessionRecord, FlowKeyHash> table_;

  // Counters
  std::size_t total_seen_ = 0;
  std::size_t classified_ = 0;
  std::size_t blocked_ = 0;

  /// Evict the least-recently-seen entry when at capacity.
  void evictLRU();
};

} // namespace sentinel
