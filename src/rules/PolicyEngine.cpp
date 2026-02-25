/// @file PolicyEngine.cpp
/// @brief JSON-driven rule management with IP/App/Domain/Port blocking.
/// @author Bibek Thakur

#include "sentinel/rules/PolicyEngine.hpp"
#include "sentinel/core/Types.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// Minimal in-line JSON parsing (no external dependency needed at this scale)
// Supports: objects, arrays of strings/numbers, string values
// ─────────────────────────────────────────────────────────────────────────────

namespace {

/// Read a JSON-style array of quoted strings from a substring: ["a","b","c"]
std::vector<std::string> parseStringArray(const std::string &text) {
  std::vector<std::string> results;
  std::size_t pos = 0;
  while (true) {
    auto q1 = text.find('"', pos);
    if (q1 == std::string::npos)
      break;
    auto q2 = text.find('"', q1 + 1);
    if (q2 == std::string::npos)
      break;
    results.push_back(text.substr(q1 + 1, q2 - q1 - 1));
    pos = q2 + 1;
  }
  return results;
}

/// Read a JSON-style array of numbers from a substring: [80, 443]
std::vector<int> parseIntArray(const std::string &text) {
  std::vector<int> results;
  std::istringstream ss(text);
  char ch;
  int val;
  while (ss >> ch) {
    if (std::isdigit(ch) || ch == '-') {
      ss.putback(ch);
      ss >> val;
      results.push_back(val);
    }
  }
  return results;
}

/// Find the value of a "key": [...] or "key": "value" in raw JSON text.
std::string findJSONValue(const std::string &json, const std::string &key) {
  std::string search = "\"" + key + "\"";
  auto pos = json.find(search);
  if (pos == std::string::npos)
    return "";
  pos = json.find(':', pos + search.size());
  if (pos == std::string::npos)
    return "";
  ++pos;
  // Skip whitespace
  while (pos < json.size() && std::isspace(json[pos]))
    ++pos;
  if (pos >= json.size())
    return "";

  if (json[pos] == '[') {
    auto end = json.find(']', pos);
    if (end == std::string::npos)
      return "";
    return json.substr(pos, end - pos + 1);
  } else if (json[pos] == '"') {
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos)
      return "";
    return json.substr(pos + 1, end - pos - 1);
  }
  return "";
}

} // anonymous namespace

namespace sentinel {

// ═══════════════════════════════════════════════════════════════════════════
// IP Blocking
// ═══════════════════════════════════════════════════════════════════════════

void PolicyEngine::blockIP(const std::string &ip) { blockIP(stringToIp(ip)); }

void PolicyEngine::blockIP(uint32_t ip) {
  std::lock_guard lock(mutex_);
  blocked_ips_.insert(ip);
}

void PolicyEngine::unblockIP(const std::string &ip) {
  unblockIP(stringToIp(ip));
}

void PolicyEngine::unblockIP(uint32_t ip) {
  std::lock_guard lock(mutex_);
  blocked_ips_.erase(ip);
}

bool PolicyEngine::isIPBlocked(uint32_t ip) const {
  std::lock_guard lock(mutex_);
  return blocked_ips_.count(ip) > 0;
}

std::vector<std::string> PolicyEngine::blockedIPs() const {
  std::lock_guard lock(mutex_);
  std::vector<std::string> result;
  result.reserve(blocked_ips_.size());
  for (auto ip : blocked_ips_) {
    result.push_back(ipToString(ip));
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// App Blocking
// ═══════════════════════════════════════════════════════════════════════════

void PolicyEngine::blockApp(AppSignature app) {
  std::lock_guard lock(mutex_);
  blocked_apps_.insert(app);
}

void PolicyEngine::unblockApp(AppSignature app) {
  std::lock_guard lock(mutex_);
  blocked_apps_.erase(app);
}

bool PolicyEngine::isAppBlocked(AppSignature app) const {
  std::lock_guard lock(mutex_);
  return blocked_apps_.count(app) > 0;
}

std::vector<AppSignature> PolicyEngine::blockedApps() const {
  std::lock_guard lock(mutex_);
  return {blocked_apps_.begin(), blocked_apps_.end()};
}

// ═══════════════════════════════════════════════════════════════════════════
// Domain Blocking
// ═══════════════════════════════════════════════════════════════════════════

void PolicyEngine::blockDomain(const std::string &domain) {
  std::lock_guard lock(mutex_);
  if (domain.find('*') != std::string::npos) {
    domain_patterns_.push_back(domain);
  } else {
    blocked_domains_.insert(domain);
  }
}

void PolicyEngine::unblockDomain(const std::string &domain) {
  std::lock_guard lock(mutex_);
  blocked_domains_.erase(domain);
  domain_patterns_.erase(
      std::remove(domain_patterns_.begin(), domain_patterns_.end(), domain),
      domain_patterns_.end());
}

bool PolicyEngine::isDomainBlocked(const std::string &domain) const {
  std::lock_guard lock(mutex_);
  if (blocked_domains_.count(domain) > 0)
    return true;
  for (const auto &pattern : domain_patterns_) {
    if (matchWildcard(domain, pattern))
      return true;
  }
  return false;
}

std::vector<std::string> PolicyEngine::blockedDomains() const {
  std::lock_guard lock(mutex_);
  std::vector<std::string> result(blocked_domains_.begin(),
                                  blocked_domains_.end());
  result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// Port Blocking
// ═══════════════════════════════════════════════════════════════════════════

void PolicyEngine::blockPort(uint16_t port) {
  std::lock_guard lock(mutex_);
  blocked_ports_.insert(port);
}

void PolicyEngine::unblockPort(uint16_t port) {
  std::lock_guard lock(mutex_);
  blocked_ports_.erase(port);
}

bool PolicyEngine::isPortBlocked(uint16_t port) const {
  std::lock_guard lock(mutex_);
  return blocked_ports_.count(port) > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Combined Evaluation
// ═══════════════════════════════════════════════════════════════════════════

std::optional<BlockReason>
PolicyEngine::evaluate(uint32_t src_ip, uint16_t dst_port, AppSignature app,
                       const std::string &domain) const {
  std::lock_guard lock(mutex_);

  if (blocked_ips_.count(src_ip)) {
    return BlockReason{BlockReason::Kind::IP,
                       "IP blocked: " + ipToString(src_ip)};
  }
  if (blocked_apps_.count(app)) {
    return BlockReason{BlockReason::Kind::App,
                       "App blocked: " + std::string(appSignatureToName(app))};
  }
  if (!domain.empty()) {
    if (blocked_domains_.count(domain)) {
      return BlockReason{BlockReason::Kind::Domain,
                         "Domain blocked: " + domain};
    }
    for (const auto &pat : domain_patterns_) {
      if (matchWildcard(domain, pat)) {
        return BlockReason{BlockReason::Kind::Domain,
                           "Domain blocked (wildcard " + pat + "): " + domain};
      }
    }
  }
  if (blocked_ports_.count(dst_port)) {
    return BlockReason{BlockReason::Kind::Port,
                       "Port blocked: " + std::to_string(dst_port)};
  }
  return std::nullopt;
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON Persistence
// ═══════════════════════════════════════════════════════════════════════════

bool PolicyEngine::loadFromJSON(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    std::cerr << "[PolicyEngine] Cannot open rules file: " << path << "\n";
    return false;
  }

  std::string json((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());

  // Parse blocked IPs
  auto ip_array = findJSONValue(json, "blocked_ips");
  for (const auto &ip : parseStringArray(ip_array)) {
    blockIP(ip);
  }

  // Parse blocked apps
  auto app_array = findJSONValue(json, "blocked_apps");
  for (const auto &name : parseStringArray(app_array)) {
    // Match name to AppSignature
    for (int i = 0; i < static_cast<int>(AppSignature::COUNT); ++i) {
      auto sig = static_cast<AppSignature>(i);
      if (std::string(appSignatureToName(sig)) == name) {
        blockApp(sig);
        break;
      }
    }
  }

  // Parse blocked domains
  auto domain_array = findJSONValue(json, "blocked_domains");
  for (const auto &d : parseStringArray(domain_array)) {
    blockDomain(d);
  }

  // Parse blocked ports
  auto port_array = findJSONValue(json, "blocked_ports");
  for (int p : parseIntArray(port_array)) {
    blockPort(static_cast<uint16_t>(p));
  }

  auto rs = ruleStats();
  std::cout << "[PolicyEngine] Loaded rules from " << path << ": "
            << rs.ip_count << " IPs, " << rs.app_count << " apps, "
            << rs.domain_count << " domains, " << rs.port_count << " ports\n";

  return true;
}

bool PolicyEngine::saveToJSON(const std::string &path) const {
  std::lock_guard lock(mutex_);

  std::ofstream file(path);
  if (!file.is_open())
    return false;

  file << "{\n";

  // Blocked IPs
  file << "  \"blocked_ips\": [";
  bool first = true;
  for (auto ip : blocked_ips_) {
    if (!first)
      file << ", ";
    file << "\"" << ipToString(ip) << "\"";
    first = false;
  }
  file << "],\n";

  // Blocked Apps
  file << "  \"blocked_apps\": [";
  first = true;
  for (auto app : blocked_apps_) {
    if (!first)
      file << ", ";
    file << "\"" << appSignatureToName(app) << "\"";
    first = false;
  }
  file << "],\n";

  // Blocked Domains
  file << "  \"blocked_domains\": [";
  first = true;
  for (const auto &d : blocked_domains_) {
    if (!first)
      file << ", ";
    file << "\"" << d << "\"";
    first = false;
  }
  for (const auto &p : domain_patterns_) {
    if (!first)
      file << ", ";
    file << "\"" << p << "\"";
    first = false;
  }
  file << "],\n";

  // Blocked Ports
  file << "  \"blocked_ports\": [";
  first = true;
  for (auto port : blocked_ports_) {
    if (!first)
      file << ", ";
    file << port;
    first = false;
  }
  file << "]\n";

  file << "}\n";
  return file.good();
}

void PolicyEngine::clearAll() {
  std::lock_guard lock(mutex_);
  blocked_ips_.clear();
  blocked_apps_.clear();
  blocked_domains_.clear();
  domain_patterns_.clear();
  blocked_ports_.clear();
}

PolicyEngine::RuleStats PolicyEngine::ruleStats() const {
  std::lock_guard lock(mutex_);
  return {blocked_ips_.size(), blocked_apps_.size(),
          blocked_domains_.size() + domain_patterns_.size(),
          blocked_ports_.size()};
}

bool PolicyEngine::matchWildcard(const std::string &domain,
                                 const std::string &pattern) {
  // Support "*.example.com" — match if domain ends with "example.com"
  if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
    std::string suffix = pattern.substr(1); // ".example.com"
    if (domain.size() >= suffix.size()) {
      return domain.compare(domain.size() - suffix.size(), suffix.size(),
                            suffix) == 0;
    }
    // Also match the bare domain (e.g. "example.com" matches "*.example.com")
    std::string bare = pattern.substr(2);
    return domain == bare;
  }
  return domain == pattern;
}

} // namespace sentinel
