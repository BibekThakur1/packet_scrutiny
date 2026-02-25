/// @file SessionLedger.cpp
/// @brief Per-thread flow table implementation with LRU eviction and stale
/// cleanup.
/// @author Bibek Thakur

#include "sentinel/flow/SessionLedger.hpp"
#include <algorithm>

namespace sentinel {

SessionLedger::SessionLedger(int ledger_id, std::size_t capacity)
    : id_(ledger_id), capacity_(capacity) {}

SessionRecord *SessionLedger::getOrCreate(const FlowKey &key) {
  auto it = table_.find(key);
  if (it != table_.end()) {
    return &it->second;
  }

  // At capacity? Evict oldest
  if (table_.size() >= capacity_) {
    evictLRU();
  }

  auto [iter, ok] = table_.emplace(key, SessionRecord{});
  if (!ok)
    return nullptr;

  auto *rec = &iter->second;
  rec->key = key;
  rec->phase = FlowPhase::Initiated;
  rec->first_seen = std::chrono::steady_clock::now();
  rec->last_seen = rec->first_seen;
  ++total_seen_;

  return rec;
}

SessionRecord *SessionLedger::find(const FlowKey &key) {
  auto it = table_.find(key);
  return (it != table_.end()) ? &it->second : nullptr;
}

void SessionLedger::recordPacket(SessionRecord *rec, std::size_t bytes,
                                 bool is_outbound) {
  if (!rec)
    return;
  rec->last_seen = std::chrono::steady_clock::now();
  if (is_outbound) {
    ++rec->packets_out;
    rec->bytes_out += bytes;
  } else {
    ++rec->packets_in;
    rec->bytes_in += bytes;
  }

  // Advance phase based on TCP handshake tracking
  if (rec->phase == FlowPhase::Initiated && rec->syn_ack_seen) {
    rec->phase = FlowPhase::Handshake;
  }
  if (rec->phase == FlowPhase::Handshake &&
      (rec->packets_in + rec->packets_out) >= 3) {
    rec->phase = FlowPhase::Active;
  }
}

void SessionLedger::classify(SessionRecord *rec, AppSignature app,
                             const std::string &sni) {
  if (!rec)
    return;
  rec->app = app;
  rec->sni = sni;
  rec->phase = FlowPhase::Classified;
  ++classified_;
}

void SessionLedger::block(SessionRecord *rec) {
  if (!rec)
    return;
  rec->verdict = Verdict::Drop;
  ++blocked_;
}

void SessionLedger::terminate(const FlowKey &key) {
  auto it = table_.find(key);
  if (it != table_.end()) {
    it->second.phase = FlowPhase::Terminated;
  }
}

std::size_t SessionLedger::evictStale(std::chrono::seconds timeout) {
  auto now = std::chrono::steady_clock::now();
  std::size_t removed = 0;

  for (auto it = table_.begin(); it != table_.end();) {
    if ((now - it->second.last_seen) > timeout) {
      it = table_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  return removed;
}

std::vector<SessionRecord> SessionLedger::snapshot() const {
  std::vector<SessionRecord> result;
  result.reserve(table_.size());
  for (const auto &[k, v] : table_) {
    result.push_back(v);
  }
  return result;
}

void SessionLedger::forEach(
    std::function<void(const SessionRecord &)> visitor) const {
  for (const auto &[k, v] : table_) {
    visitor(v);
  }
}

SessionLedger::Stats SessionLedger::stats() const noexcept {
  return {table_.size(), total_seen_, classified_, blocked_};
}

void SessionLedger::clear() {
  table_.clear();
  total_seen_ = classified_ = blocked_ = 0;
}

void SessionLedger::evictLRU() {
  if (table_.empty())
    return;
  auto oldest = table_.begin();
  for (auto it = table_.begin(); it != table_.end(); ++it) {
    if (it->second.last_seen < oldest->second.last_seen) {
      oldest = it;
    }
  }
  table_.erase(oldest);
}

} // namespace sentinel
