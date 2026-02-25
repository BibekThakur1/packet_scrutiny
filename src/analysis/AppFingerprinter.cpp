/// @file AppFingerprinter.cpp
/// @brief Application classification via SNI domain matching and port
/// heuristics.
/// @author Bibek Thakur

#include "sentinel/analysis/AppFingerprinter.hpp"
#include <algorithm>
#include <cctype>

namespace sentinel {

AppFingerprinter::AppFingerprinter() { loadDefaults(); }

void AppFingerprinter::loadDefaults() {
  // Domain suffix → AppSignature mapping
  domain_rules_ = {
      {".google.com", AppSignature::Google},
      {".googleapis.com", AppSignature::Google},
      {".gstatic.com", AppSignature::Google},
      {".youtube.com", AppSignature::YouTube},
      {".ytimg.com", AppSignature::YouTube},
      {".googlevideo.com", AppSignature::YouTube},
      {".facebook.com", AppSignature::Facebook},
      {".fbcdn.net", AppSignature::Facebook},
      {".fb.com", AppSignature::Facebook},
      {".instagram.com", AppSignature::Instagram},
      {".cdninstagram.com", AppSignature::Instagram},
      {".twitter.com", AppSignature::Twitter},
      {".twimg.com", AppSignature::Twitter},
      {".x.com", AppSignature::Twitter},
      {".netflix.com", AppSignature::Netflix},
      {".nflxvideo.net", AppSignature::Netflix},
      {".amazon.com", AppSignature::Amazon},
      {".amazonaws.com", AppSignature::Amazon},
      {".microsoft.com", AppSignature::Microsoft},
      {".windows.net", AppSignature::Microsoft},
      {".office.com", AppSignature::Microsoft},
      {".apple.com", AppSignature::Apple},
      {".icloud.com", AppSignature::Apple},
      {".whatsapp.net", AppSignature::WhatsApp},
      {".whatsapp.com", AppSignature::WhatsApp},
      {".telegram.org", AppSignature::Telegram},
      {".tiktok.com", AppSignature::TikTok},
      {".tiktokcdn.com", AppSignature::TikTok},
      {".spotify.com", AppSignature::Spotify},
      {".scdn.co", AppSignature::Spotify},
      {".zoom.us", AppSignature::Zoom},
      {".zoom.com", AppSignature::Zoom},
      {".discord.com", AppSignature::Discord},
      {".discordapp.com", AppSignature::Discord},
      {".github.com", AppSignature::GitHub},
      {".githubusercontent.com", AppSignature::GitHub},
      {".cloudflare.com", AppSignature::Cloudflare},
      {".reddit.com", AppSignature::Reddit},
      {".redd.it", AppSignature::Reddit},
      {".linkedin.com", AppSignature::LinkedIn},
  };

  // Port-based fallback heuristics
  port_rules_ = {
      {80, AppSignature::HTTP},    {443, AppSignature::HTTPS},
      {53, AppSignature::DNS},     {8080, AppSignature::HTTP},
      {8443, AppSignature::HTTPS},
  };
}

AppSignature AppFingerprinter::classifyBySNI(const std::string &sni) const {
  if (sni.empty())
    return AppSignature::Unknown;

  // Normalise to lowercase
  std::string lower = sni;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Prepend a dot so "facebook.com" becomes ".facebook.com" and matches the
  // suffix
  std::string dotted = "." + lower;

  for (const auto &rule : domain_rules_) {
    if (dotted.size() >= rule.suffix.size()) {
      if (dotted.compare(dotted.size() - rule.suffix.size(), rule.suffix.size(),
                         rule.suffix) == 0) {
        return rule.sig;
      }
    }
  }

  // Also check exact match (e.g. sni == "facebook.com")
  for (const auto &rule : domain_rules_) {
    // rule.suffix is ".facebook.com", check if lower == "facebook.com"
    if (rule.suffix.size() > 1 && lower == rule.suffix.substr(1)) {
      return rule.sig;
    }
  }

  return AppSignature::Unknown;
}

AppSignature AppFingerprinter::classifyByPort(uint16_t dst_port) const {
  auto it = port_rules_.find(dst_port);
  return (it != port_rules_.end()) ? it->second : AppSignature::Unknown;
}

AppSignature AppFingerprinter::classify(const std::string &sni,
                                        uint16_t dst_port) const {
  auto result = classifyBySNI(sni);
  if (result != AppSignature::Unknown)
    return result;
  return classifyByPort(dst_port);
}

} // namespace sentinel
