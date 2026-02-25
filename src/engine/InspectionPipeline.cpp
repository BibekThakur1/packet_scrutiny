/// @file InspectionPipeline.cpp
/// @brief Top-level pipeline: capture → dissect → track → classify → enforce →
/// output.
/// @author Bibek Thakur

#include "sentinel/engine/InspectionPipeline.hpp"
#include <iomanip>
#include <iostream>

namespace sentinel {

InspectionPipeline::InspectionPipeline(const Config &cfg) : cfg_(cfg) {}

bool InspectionPipeline::initialise() {
  // Create subsystems
  policy_ = std::make_unique<PolicyEngine>();
  ledger_ = std::make_unique<SessionLedger>(0);
  orchestrator_ = std::make_unique<FlowOrchestrator>(1);
  orchestrator_->registerLedger(0, ledger_.get());

  // Load rules if a file was specified
  if (!cfg_.rules_file.empty()) {
    if (!policy_->loadFromJSON(cfg_.rules_file)) {
      std::cerr << "[Pipeline] Warning: could not load rules from "
                << cfg_.rules_file << "\n";
    }
  }

  std::cout << "[Pipeline] Initialised successfully\n";
  return true;
}

bool InspectionPipeline::run(const std::string &input_pcap,
                             const std::string &output_pcap) {
  // Open input
  PcapIngester ingester;
  if (!ingester.open(input_pcap)) {
    std::cerr << "[Pipeline] Failed to open input: " << input_pcap << "\n";
    return false;
  }

  // Open output
  PcapWriter writer;
  if (!writer.open(output_pcap)) {
    std::cerr << "[Pipeline] Failed to open output: " << output_pcap << "\n";
    return false;
  }
  writer.writeGlobalHeader(ingester.globalHeader());

  std::cout << "\n"
            << "┌──────────────────────────────────────────┐\n"
            << "│     PacketScrutiny — Processing PCAP     │\n"
            << "├──────────────────────────────────────────┤\n"
            << "│  Input  : " << std::setw(29) << std::left << input_pcap
            << " │\n"
            << "│  Output : " << std::setw(29) << std::left << output_pcap
            << " │\n"
            << "└──────────────────────────────────────────┘\n\n";

  // Process frames
  if (cfg_.benchmark)
    stopwatch_.start("Total");

  uint32_t pkt_id = 0;
  ingester.forEachFrame(
      [&](const RawFrame &frame) { processFrame(frame, pkt_id++, writer); });

  if (cfg_.benchmark)
    stopwatch_.stop("Total");

  ingester.close();
  writer.close();

  // Update final metrics
  metrics_.active_connections = ledger_->activeCount();

  // Print reports
  std::cout << metrics_.toReport();
  std::cout << orchestrator_->generateReport();

  if (cfg_.benchmark) {
    std::cout << stopwatch_.report();
  }

  return true;
}

Verdict InspectionPipeline::processFrame(const RawFrame &frame, uint32_t pkt_id,
                                         PcapWriter &writer) {
  // ── Stage 1: Dissect ──
  if (cfg_.benchmark)
    stopwatch_.start("Dissect");
  DissectedFrame df;
  bool ok = FrameDissector::dissect(frame, df);
  if (cfg_.benchmark)
    stopwatch_.stop("Dissect");

  if (!ok) {
    ++metrics_.total_packets;
    ++metrics_.total_bytes += frame.data.size();
    ++metrics_.other_packets;
    return Verdict::Forward; // Can't parse — just forward
  }

  metrics_.total_packets++;
  metrics_.total_bytes += frame.data.size();

  // Count by protocol
  if (df.has_tcp)
    ++metrics_.tcp_packets;
  else if (df.has_udp)
    ++metrics_.udp_packets;
  else
    ++metrics_.other_packets;

  // Build envelope
  PacketEnvelope env = FrameDissector::toEnvelope(frame, df, pkt_id);

  // ── Stage 2: Flow Tracking ──
  if (cfg_.benchmark)
    stopwatch_.start("FlowTrack");
  SessionRecord *rec = nullptr;
  if (df.has_ip) {
    rec = ledger_->getOrCreate(env.key);
    if (rec) {
      ledger_->recordPacket(rec, frame.data.size(), true);

      // Track TCP handshake
      if (df.has_tcp) {
        if (df.tcp_flags & tcp_flag::kSYN) {
          if (df.tcp_flags & tcp_flag::kACK) {
            rec->syn_ack_seen = true;
          } else {
            rec->syn_seen = true;
          }
        }
        if (df.tcp_flags & tcp_flag::kFIN) {
          rec->fin_seen = true;
          ledger_->terminate(env.key);
        }
      }
    }
  }
  if (cfg_.benchmark)
    stopwatch_.stop("FlowTrack");

  // ── Stage 3: Classification ──
  if (cfg_.benchmark)
    stopwatch_.start("Classify");
  if (rec && rec->app == AppSignature::Unknown) {
    // Try TLS SNI extraction first
    if (df.has_tcp && df.payload_length > 0 && df.payload_ptr) {
      auto sni = TlsProber::extractSNI(df.payload_ptr, df.payload_length);
      if (sni) {
        auto app = fingerprinter_.classifyBySNI(*sni);
        if (app == AppSignature::Unknown) {
          app = AppSignature::HTTPS; // We know it's TLS at least
        }
        ledger_->classify(rec, app, *sni);

        if (cfg_.verbose) {
          std::cout << "  [SNI] Pkt#" << pkt_id << " → " << *sni << " ("
                    << appSignatureToName(app) << ")\n";
        }
      }
    }
    // Fallback: classify by port
    if (rec->app == AppSignature::Unknown && (df.has_tcp || df.has_udp)) {
      auto app = fingerprinter_.classifyByPort(df.dst_port);
      if (app != AppSignature::Unknown) {
        ledger_->classify(rec, app, "");
      }
    }
  }
  if (cfg_.benchmark)
    stopwatch_.stop("Classify");

  // ── Stage 4: Policy Enforcement ──
  if (cfg_.benchmark)
    stopwatch_.start("Enforce");
  Verdict verdict = Verdict::Forward;
  if (df.has_ip) {
    std::string domain = rec ? rec->sni : "";
    AppSignature app = rec ? rec->app : AppSignature::Unknown;

    auto block = policy_->evaluate(df.src_ip_raw, df.dst_port, app, domain);
    if (block) {
      verdict = Verdict::Drop;
      if (rec)
        ledger_->block(rec);
      if (cfg_.verbose) {
        std::cout << "  [DROP] Pkt#" << pkt_id << " — " << block->detail
                  << "\n";
      }
    }
  }
  if (cfg_.benchmark)
    stopwatch_.stop("Enforce");

  // ── Stage 5: Output ──
  if (cfg_.benchmark)
    stopwatch_.start("Output");
  if (verdict == Verdict::Forward || verdict == Verdict::LogOnly) {
    writer.writePacket(env);
    ++metrics_.forwarded_packets;
  } else {
    ++metrics_.dropped_packets;
  }
  if (cfg_.benchmark)
    stopwatch_.stop("Output");

  return verdict;
}

// ── Rule Management Façade ──────────────────────────────────────────────────

void InspectionPipeline::blockIP(const std::string &ip) {
  policy_->blockIP(ip);
}

void InspectionPipeline::blockApp(const std::string &app_name) {
  for (int i = 0; i < static_cast<int>(AppSignature::COUNT); ++i) {
    auto sig = static_cast<AppSignature>(i);
    if (std::string(appSignatureToName(sig)) == app_name) {
      policy_->blockApp(sig);
      return;
    }
  }
  std::cerr << "[Pipeline] Unknown app: " << app_name << "\n";
}

void InspectionPipeline::blockDomain(const std::string &domain) {
  policy_->blockDomain(domain);
}

void InspectionPipeline::blockPort(uint16_t port) { policy_->blockPort(port); }

// ── Reporting ───────────────────────────────────────────────────────────────

std::string InspectionPipeline::generateReport() const {
  std::string report;
  report += metrics_.toReport();
  report += orchestrator_->generateReport();
  if (cfg_.benchmark) {
    report += stopwatch_.report();
  }
  return report;
}

} // namespace sentinel
