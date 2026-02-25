/// @file InspectionPipeline.hpp
/// @brief Top-level orchestrator that wires capture, dissection, flow tracking,
///        classification, policy enforcement, and output together.
/// @author Bibek Thakur

#pragma once

#include "sentinel/analysis/AppFingerprinter.hpp"
#include "sentinel/analysis/TlsProber.hpp"
#include "sentinel/benchmark/Stopwatch.hpp"
#include "sentinel/capture/FrameDissector.hpp"
#include "sentinel/capture/PcapIngester.hpp"
#include "sentinel/core/Types.hpp"
#include "sentinel/flow/FlowOrchestrator.hpp"
#include "sentinel/flow/SessionLedger.hpp"
#include "sentinel/rules/PolicyEngine.hpp"
#include <memory>
#include <string>

namespace sentinel {

// ─────────────────────────────────────────────────────────────────────────────
// InspectionPipeline — Main entry point for the DPI engine
//
// Pipeline stages:
//   1. Capture    — read frames from a PCAP file (PcapIngester)
//   2. Dissect    — parse protocol headers (FrameDissector)
//   3. Track      — update / create flow state (SessionLedger)
//   4. Classify   — identify the application (TlsProber + AppFingerprinter)
//   5. Enforce    — check rules / policies (PolicyEngine)
//   6. Output     — write allowed packets to an output PCAP (PcapWriter)
//   7. Report     — print summary statistics and benchmarks
// ─────────────────────────────────────────────────────────────────────────────
class InspectionPipeline {
public:
  /// Configuration knobs.
  struct Config {
    std::string rules_file; ///< Path to rules.json
    bool verbose = false;   ///< Verbose per-packet logging
    bool benchmark = false; ///< Print timing breakdown
  };

  explicit InspectionPipeline(const Config &cfg);
  ~InspectionPipeline() = default;

  // Non-copyable, movable
  InspectionPipeline(const InspectionPipeline &) = delete;
  InspectionPipeline &operator=(const InspectionPipeline &) = delete;
  InspectionPipeline(InspectionPipeline &&) = default;
  InspectionPipeline &operator=(InspectionPipeline &&) = default;

  /// Initialise subsystems (load rules, etc.). Returns false on failure.
  [[nodiscard]] bool initialise();

  /// Run the full pipeline: read input_pcap → process → write output_pcap.
  [[nodiscard]] bool run(const std::string &input_pcap,
                         const std::string &output_pcap);

  // ── Rule Management Façade ──────────────────────────────────────────
  void blockIP(const std::string &ip);
  void blockApp(const std::string &app_name);
  void blockDomain(const std::string &domain);
  void blockPort(uint16_t port);

  // ── Reporting ───────────────────────────────────────────────────────
  /// Generate the full engine report (stats + classification + benchmark).
  [[nodiscard]] std::string generateReport() const;

  /// Access the metrics snapshot.
  [[nodiscard]] const EngineMetrics &metrics() const noexcept {
    return metrics_;
  }

  /// Access the policy engine.
  [[nodiscard]] PolicyEngine &policyEngine() noexcept { return *policy_; }

private:
  Config cfg_;

  std::unique_ptr<PolicyEngine> policy_;
  std::unique_ptr<SessionLedger> ledger_;
  std::unique_ptr<FlowOrchestrator> orchestrator_;
  AppFingerprinter fingerprinter_;

  EngineMetrics metrics_;
  Stopwatch stopwatch_;

  /// Process a single frame through all pipeline stages. Returns the verdict.
  Verdict processFrame(const RawFrame &frame, uint32_t pkt_id,
                       PcapWriter &writer);
};

} // namespace sentinel
