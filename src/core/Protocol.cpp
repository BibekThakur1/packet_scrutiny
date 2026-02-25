/// @file Protocol.cpp
/// @brief Implementation of protocol utility functions.
/// @author Bibek Thakur

#include "sentinel/core/Protocol.hpp"
#include <algorithm>
#include <sstream>

namespace sentinel {

std::string_view appSignatureToName(AppSignature sig) noexcept {
  switch (sig) {
  case AppSignature::Unknown:
    return "Unknown";
  case AppSignature::HTTP:
    return "HTTP";
  case AppSignature::HTTPS:
    return "HTTPS";
  case AppSignature::DNS:
    return "DNS";
  case AppSignature::TLS:
    return "TLS";
  case AppSignature::QUIC:
    return "QUIC";
  case AppSignature::Google:
    return "Google";
  case AppSignature::Facebook:
    return "Facebook";
  case AppSignature::YouTube:
    return "YouTube";
  case AppSignature::Twitter:
    return "Twitter";
  case AppSignature::Instagram:
    return "Instagram";
  case AppSignature::Netflix:
    return "Netflix";
  case AppSignature::Amazon:
    return "Amazon";
  case AppSignature::Microsoft:
    return "Microsoft";
  case AppSignature::Apple:
    return "Apple";
  case AppSignature::WhatsApp:
    return "WhatsApp";
  case AppSignature::Telegram:
    return "Telegram";
  case AppSignature::TikTok:
    return "TikTok";
  case AppSignature::Spotify:
    return "Spotify";
  case AppSignature::Zoom:
    return "Zoom";
  case AppSignature::Discord:
    return "Discord";
  case AppSignature::GitHub:
    return "GitHub";
  case AppSignature::Cloudflare:
    return "Cloudflare";
  case AppSignature::Reddit:
    return "Reddit";
  case AppSignature::LinkedIn:
    return "LinkedIn";
  default:
    return "Unknown";
  }
}

AppSignature sniToAppSignature(const std::string &sni) noexcept {
  // Convert to lowercase for matching
  std::string lower = sni;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  struct Rule {
    const char *suffix;
    AppSignature sig;
  };
  static constexpr Rule rules[] = {
      {"google.com", AppSignature::Google},
      {"googleapis.com", AppSignature::Google},
      {"gstatic.com", AppSignature::Google},
      {"youtube.com", AppSignature::YouTube},
      {"ytimg.com", AppSignature::YouTube},
      {"googlevideo.com", AppSignature::YouTube},
      {"facebook.com", AppSignature::Facebook},
      {"fbcdn.net", AppSignature::Facebook},
      {"fb.com", AppSignature::Facebook},
      {"instagram.com", AppSignature::Instagram},
      {"cdninstagram.com", AppSignature::Instagram},
      {"twitter.com", AppSignature::Twitter},
      {"twimg.com", AppSignature::Twitter},
      {"x.com", AppSignature::Twitter},
      {"netflix.com", AppSignature::Netflix},
      {"nflxvideo.net", AppSignature::Netflix},
      {"amazon.com", AppSignature::Amazon},
      {"amazonaws.com", AppSignature::Amazon},
      {"microsoft.com", AppSignature::Microsoft},
      {"windows.net", AppSignature::Microsoft},
      {"office.com", AppSignature::Microsoft},
      {"apple.com", AppSignature::Apple},
      {"icloud.com", AppSignature::Apple},
      {"whatsapp.net", AppSignature::WhatsApp},
      {"whatsapp.com", AppSignature::WhatsApp},
      {"telegram.org", AppSignature::Telegram},
      {"t.me", AppSignature::Telegram},
      {"tiktok.com", AppSignature::TikTok},
      {"tiktokcdn.com", AppSignature::TikTok},
      {"spotify.com", AppSignature::Spotify},
      {"scdn.co", AppSignature::Spotify},
      {"zoom.us", AppSignature::Zoom},
      {"zoom.com", AppSignature::Zoom},
      {"discord.com", AppSignature::Discord},
      {"discordapp.com", AppSignature::Discord},
      {"github.com", AppSignature::GitHub},
      {"githubusercontent.com", AppSignature::GitHub},
      {"cloudflare.com", AppSignature::Cloudflare},
      {"cloudflare-dns.com", AppSignature::Cloudflare},
      {"reddit.com", AppSignature::Reddit},
      {"redd.it", AppSignature::Reddit},
      {"linkedin.com", AppSignature::LinkedIn},
  };

  for (const auto &rule : rules) {
    if (lower.size() >= std::strlen(rule.suffix)) {
      auto pos = lower.rfind(rule.suffix);
      if (pos != std::string::npos &&
          pos + std::strlen(rule.suffix) == lower.size()) {
        // Ensure it's a domain boundary (start of string or preceded by '.')
        if (pos == 0 || lower[pos - 1] == '.') {
          return rule.sig;
        }
      }
    }
  }
  return AppSignature::Unknown;
}

std::string tcpFlagsToString(uint8_t flags) {
  std::string result = "[";
  if (flags & tcp_flag::kSYN)
    result += "SYN ";
  if (flags & tcp_flag::kACK)
    result += "ACK ";
  if (flags & tcp_flag::kFIN)
    result += "FIN ";
  if (flags & tcp_flag::kRST)
    result += "RST ";
  if (flags & tcp_flag::kPSH)
    result += "PSH ";
  if (flags & tcp_flag::kURG)
    result += "URG ";
  if (result.size() > 1 && result.back() == ' ') {
    result.pop_back();
  }
  result += "]";
  return result;
}

std::string_view protocolNumberToName(uint8_t proto) noexcept {
  switch (proto) {
  case ip_proto::kTCP:
    return "TCP";
  case ip_proto::kUDP:
    return "UDP";
  case ip_proto::kICMP:
    return "ICMP";
  default:
    return "OTHER";
  }
}

} // namespace sentinel
