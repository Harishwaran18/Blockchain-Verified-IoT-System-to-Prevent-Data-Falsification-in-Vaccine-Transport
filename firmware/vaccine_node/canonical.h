// Canonical telemetry encoding shared by the ESP32 firmware and host tests.
//
// The byte order must match Python's canonical_json(): keys sorted
// alphabetically, no whitespace, ASCII only, fixed-point integers.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace vchain {

inline void appendJsonString(std::string &out, const std::string &value) {
  out.push_back('"');
  for (unsigned char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buffer[7];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
          out += buffer;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
}

struct ReadingPayload {
  std::string device_id;
  std::string firmware;
  int gps_fix;
  int32_t humidity_milli_pct;
  int32_t lat_e7;
  int32_t lon_e7;
  std::string measured_at;
  std::string nonce;
  uint32_t seq;
  int32_t temperature_centi_c;
};

inline std::string canonicalPayload(const ReadingPayload &reading) {
  std::string out;
  out.reserve(320);
  out += "{\"device_id\":";
  appendJsonString(out, reading.device_id);
  out += ",\"firmware\":";
  appendJsonString(out, reading.firmware);
  out += ",\"gps_fix\":";
  out += std::to_string(reading.gps_fix);
  out += ",\"humidity_milli_pct\":";
  out += std::to_string(reading.humidity_milli_pct);
  out += ",\"lat_e7\":";
  out += std::to_string(reading.lat_e7);
  out += ",\"lon_e7\":";
  out += std::to_string(reading.lon_e7);
  out += ",\"measured_at\":";
  appendJsonString(out, reading.measured_at);
  out += ",\"nonce\":";
  appendJsonString(out, reading.nonce);
  out += ",\"seq\":";
  out += std::to_string(reading.seq);
  out += ",\"temperature_centi_c\":";
  out += std::to_string(reading.temperature_centi_c);
  out.push_back('}');
  return out;
}

inline std::string envelope(const std::string &canonical_payload,
                            const std::string &digest_hex,
                            const std::string &signature_hex) {
  std::string out;
  out.reserve(canonical_payload.size() + 220);
  out += "{\"alg\":\"HMAC-SHA256\",\"digest\":\"";
  out += digest_hex;
  out += "\",\"payload\":";
  out += canonical_payload;
  out += ",\"signature\":\"";
  out += signature_hex;
  out += "\"}";
  return out;
}

}  // namespace vchain
