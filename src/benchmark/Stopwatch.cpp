/// @file Stopwatch.cpp
/// @brief Performance benchmarking timer implementation.
/// @author Bibek Thakur

#include "sentinel/benchmark/Stopwatch.hpp"
#include <iomanip>
#include <sstream>

namespace sentinel {

void Stopwatch::start(const std::string &stage) {
  auto it = stages_.find(stage);
  if (it == stages_.end()) {
    order_.push_back(stage);
    stages_[stage] = StageData{};
    it = stages_.find(stage);
  }
  it->second.start_time = Clock::now();
  it->second.running = true;
}

void Stopwatch::stop(const std::string &stage) {
  auto it = stages_.find(stage);
  if (it == stages_.end() || !it->second.running)
    return;
  auto now = Clock::now();
  it->second.accumulated +=
      std::chrono::duration_cast<Duration>(now - it->second.start_time);
  it->second.running = false;
}

Stopwatch::Duration Stopwatch::elapsed(const std::string &stage) const {
  auto it = stages_.find(stage);
  if (it == stages_.end())
    return Duration{0};
  return it->second.accumulated;
}

double Stopwatch::elapsedMs(const std::string &stage) const {
  auto d = elapsed(stage);
  return std::chrono::duration<double, std::milli>(d).count();
}

void Stopwatch::reset() {
  stages_.clear();
  order_.clear();
}

std::string Stopwatch::report() const {
  std::ostringstream os;
  os << "\n╔══════════════════════════════════════════╗\n"
     << "║       Performance Benchmark Report       ║\n"
     << "╠══════════════════════════════════════════╣\n";

  Duration total{0};
  for (const auto &name : order_) {
    auto it = stages_.find(name);
    if (it == stages_.end())
      continue;
    total += it->second.accumulated;
  }

  for (const auto &name : order_) {
    auto it = stages_.find(name);
    if (it == stages_.end())
      continue;
    double ms =
        std::chrono::duration<double, std::milli>(it->second.accumulated)
            .count();
    double pct = (total.count() > 0)
                     ? 100.0 *
                           static_cast<double>(it->second.accumulated.count()) /
                           static_cast<double>(total.count())
                     : 0.0;

    os << "║  " << std::setw(18) << std::left << name << " : " << std::setw(10)
       << std::right << std::fixed << std::setprecision(3) << ms << " ms ("
       << std::setw(5) << std::setprecision(1) << pct << "%) ║\n";
  }

  double total_ms = std::chrono::duration<double, std::milli>(total).count();
  os << "╠══════════════════════════════════════════╣\n"
     << "║  " << std::setw(18) << std::left << "Total"
     << " : " << std::setw(10) << std::right << std::fixed
     << std::setprecision(3) << total_ms << " ms          ║\n"
     << "╚══════════════════════════════════════════╝\n";

  return os.str();
}

} // namespace sentinel
