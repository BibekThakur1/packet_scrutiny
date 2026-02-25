/// @file Stopwatch.hpp
/// @brief High-resolution timing utilities for performance benchmarking.
/// @author Bibek Thakur

#pragma once

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// Stopwatch — Measures elapsed wall-clock time for individual pipeline stages.
//
// Usage:
//   Stopwatch sw;
//   sw.start("Capture");
//   // ... do work ...
//   sw.stop("Capture");
//   sw.start("Dissect");
//   // ... do work ...
//   sw.stop("Dissect");
//   std::cout << sw.report();
// ─────────────────────────────────────────────────────────────────────────────
class Stopwatch {
public:
  using Clock = std::chrono::high_resolution_clock;
  using TimePoint = Clock::time_point;
  using Duration = std::chrono::nanoseconds;

  /// Start timing a named stage. If already running, restarts.
  void start(const std::string &stage);

  /// Stop timing a named stage and accumulate elapsed time.
  void stop(const std::string &stage);

  /// Get accumulated duration for a stage.
  [[nodiscard]] Duration elapsed(const std::string &stage) const;

  /// Get accumulated duration in milliseconds.
  [[nodiscard]] double elapsedMs(const std::string &stage) const;

  /// Reset all timers.
  void reset();

  /// Generate a formatted benchmark report.
  [[nodiscard]] std::string report() const;

private:
  struct StageData {
    TimePoint start_time;
    Duration accumulated{0};
    bool running = false;
  };
  std::unordered_map<std::string, StageData> stages_;
  std::vector<std::string> order_; ///< Insertion order for reporting
};

} // namespace sentinel
