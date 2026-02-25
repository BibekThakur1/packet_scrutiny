/// @file main.cpp
/// @brief NetSentinel CLI entry point.
/// @author Bibek Thakur
///
/// Usage:
///   net_sentinel --input <pcap> --output <pcap> [--rules <json>] [--verbose]
///   [--benchmark]

#include "sentinel/engine/InspectionPipeline.hpp"
#include <cstring>
#include <iostream>
#include <string>

static void printUsage(const char *prog) {
  std::cout << "\n"
            << "╔══════════════════════════════════════════════════════╗\n"
            << "║           PacketScrutiny v1.0.0                     ║\n"
            << "║   Deep Packet Inspection Engine for Education       ║\n"
            << "║   Author: Bibek Thakur                              ║\n"
            << "╚══════════════════════════════════════════════════════╝\n"
            << "\n"
            << "Usage: " << prog << " [options]\n\n"
            << "Required:\n"
            << "  --input  <file>    Input PCAP file to analyse\n"
            << "  --output <file>    Output PCAP file (forwarded packets)\n"
            << "\n"
            << "Optional:\n"
            << "  --rules  <file>    JSON rules file for blocking policies\n"
            << "  --verbose          Print per-packet details\n"
            << "  --benchmark        Print per-stage timing breakdown\n"
            << "  --help             Show this help message\n"
            << "\n"
            << "Examples:\n"
            << "  " << prog << " --input traffic.pcap --output clean.pcap\n"
            << "  " << prog
            << " --input traffic.pcap --output clean.pcap --rules rules.json "
               "--benchmark\n"
            << "\n";
}

int main(int argc, char *argv[]) {
  std::string input_file;
  std::string output_file;
  sentinel::InspectionPipeline::Config cfg;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
      input_file = argv[++i];
    } else if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
      output_file = argv[++i];
    } else if (std::strcmp(argv[i], "--rules") == 0 && i + 1 < argc) {
      cfg.rules_file = argv[++i];
    } else if (std::strcmp(argv[i], "--verbose") == 0) {
      cfg.verbose = true;
    } else if (std::strcmp(argv[i], "--benchmark") == 0) {
      cfg.benchmark = true;
    } else if (std::strcmp(argv[i], "--help") == 0) {
      printUsage(argv[0]);
      return 0;
    } else {
      std::cerr << "Unknown option: " << argv[i] << "\n";
      printUsage(argv[0]);
      return 1;
    }
  }

  if (input_file.empty() || output_file.empty()) {
    std::cerr << "Error: --input and --output are required.\n";
    printUsage(argv[0]);
    return 1;
  }

  // Banner
  std::cout << "\n"
            << "  ┌──────────────────────────────────────────────┐\n"
            << "  │  █▀█ ▄▀█ █▀▀ █▄▀ █▀▀ ▀█▀                   │\n"
            << "  │  █▀▀ █▀█ █▄▄ █░█ ██▄ ░█░                   │\n"
            << "  │  █▀ █▀▀ █▀█ █░█ ▀█▀ █ █▄░█ █▄█             │\n"
            << "  │  ▄█ █▄▄ █▀▄ █▄█ ░█░ █ █░▀█ ░█░             │\n"
            << "  │       Deep Packet Inspection Engine          │\n"
            << "  │             v1.0.0 — 2026                    │\n"
            << "  └──────────────────────────────────────────────┘\n\n";

  // Build and run pipeline
  sentinel::InspectionPipeline pipeline(cfg);

  if (!pipeline.initialise()) {
    std::cerr << "[main] Failed to initialise pipeline.\n";
    return 1;
  }

  if (!pipeline.run(input_file, output_file)) {
    std::cerr << "[main] Pipeline run failed.\n";
    return 1;
  }

  std::cout << "\n[main] Done. Output written to: " << output_file << "\n\n";
  return 0;
}
