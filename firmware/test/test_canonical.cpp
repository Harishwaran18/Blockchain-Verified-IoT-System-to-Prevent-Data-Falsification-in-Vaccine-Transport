// Host-side parity test for the canonical encoder.
// Build: g++ -std=c++17 -O2 firmware/test/test_canonical.cpp -o /tmp/test_canonical
#include <iostream>

#include "../vaccine_node/canonical.h"

int main() {
  vchain::ReadingPayload reading{
      "VX-001",
      "1.0.0",
      1,
      45250,
      407128000,
      -740059000,
      "2026-11-22T09:10:00.123Z",
      "a1b2c3d4e5f60718",
      42,
      512,
  };
  std::cout << vchain::canonicalPayload(reading) << "\n";

  vchain::ReadingPayload escaped{
      "VX-002",
      "1.0.0",
      0,
      0,
      -1,
      -2,
      "2026-01-01T00:00:00.000Z",
      "0000000000000000",
      0,
      -1250,
  };
  std::cout << vchain::canonicalPayload(escaped) << "\n";
  std::cout << vchain::envelope("{}", "aa", "bb") << "\n";
  return 0;
}
