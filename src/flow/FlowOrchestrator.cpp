/// @file FlowOrchestrator.cpp
/// @brief Cross-ledger flow aggregation and reporting.
/// @author Bibek Thakur

#include "sentinel/flow/FlowOrchestrator.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace sentinel {

FlowOrchestrator::FlowOrchestrator(std::size_t num_ledgers) {
  ledgers_.reserve(num_ledgers);
}

void FlowOrchestrator::registerLedger(int /*id*/, SessionLedger *ledger) {
  std::lock_guard lock(mutex_);
  ledgers_.push_back(ledger);
}

FlowOrchestrator::GlobalStats FlowOrchestrator::aggregate() const {
  std::lock_guard lock(mutex_);

  GlobalStats gs;
  std::unordered_map<std::string, std::size_t> domain_counts;

  for (const auto *ledger : ledgers_) {
    if (!ledger)
      continue;
    auto s = ledger->stats();
    gs.total_active += s.active;
    gs.total_seen += s.total_seen;

    ledger->forEach([&](const SessionRecord &rec) {
      if (rec.app != AppSignature::Unknown) {
        gs.app_distribution[rec.app]++;
      }
      if (!rec.sni.empty()) {
        domain_counts[rec.sni]++;
      }
    });
  }

  // Sort domains by frequency (top 20)
  std::vector<std::pair<std::string, std::size_t>> sorted_domains(
      domain_counts.begin(), domain_counts.end());
  std::sort(sorted_domains.begin(), sorted_domains.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
  if (sorted_domains.size() > 20)
    sorted_domains.resize(20);
  gs.top_domains = std::move(sorted_domains);

  return gs;
}

std::string FlowOrchestrator::generateReport() const {
  auto gs = aggregate();

  std::ostringstream os;
  os << "\n╔══════════════════════════════════════════╗\n"
     << "║      Flow Classification Report          ║\n"
     << "╠══════════════════════════════════════════╣\n"
     << "║  Active Flows    : " << std::setw(19) << gs.total_active << " ║\n"
     << "║  Total Seen      : " << std::setw(19) << gs.total_seen << " ║\n"
     << "╠══════════════════════════════════════════╣\n"
     << "║  Application Distribution                ║\n"
     << "╠══════════════════════════════════════════╣\n";

  for (const auto &[app, count] : gs.app_distribution) {
    auto name = appSignatureToName(app);
    os << "║  " << std::setw(20) << std::left << name << " : " << std::setw(15)
       << std::right << count << " ║\n";
  }

  if (!gs.top_domains.empty()) {
    os << "╠══════════════════════════════════════════╣\n"
       << "║  Top Domains                             ║\n"
       << "╠══════════════════════════════════════════╣\n";
    for (const auto &[domain, count] : gs.top_domains) {
      std::string d = domain;
      if (d.size() > 25)
        d = "..." + d.substr(d.size() - 22);
      os << "║  " << std::setw(25) << std::left << d << " : " << std::setw(10)
         << std::right << count << " ║\n";
    }
  }

  os << "╚══════════════════════════════════════════╝\n";
  return os.str();
}

} // namespace sentinel
