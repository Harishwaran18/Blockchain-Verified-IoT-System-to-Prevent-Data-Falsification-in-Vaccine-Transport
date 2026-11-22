/*
 * VChain vaccine-transport node
 * -----------------------------
 * ESP32 + DHT22 + NEO-6M GPS. Each wake cycle:
 *   1. read temperature, humidity and position,
 *   2. build the canonical fixed-point payload (shared with the gateway),
 *   3. SHA-256 hash the payload with its domain prefix,
 *   4. HMAC-SHA256 sign the digest with the provisioned device key,
 *   5. publish the signed envelope to MQTT,
 *   6. deep-sleep until the next sample.
 *
 * Libraries (Arduino Library Manager):
 *   DHT sensor library (Adafruit), TinyGPSPlus (Mikal Hart), PubSubClient (Nick O'Leary)
 * Board: ESP32 Dev Module. See firmware/README.md for wiring and provisioning.
 */

#include <Arduino.h>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <TinyGPS++.h>
#include <esp_sleep.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <time.h>

#include "config.h"
#include "canonical.h"

static const char *kReadingDomain = "VCHAIN/reading/v1:";

RTC_DATA_ATTR uint32_t gSequence = 0;
RTC_DATA_ATTR uint32_t gWakeCount = 0;

HardwareSerial gpsSerial(2);
TinyGPSPlus gps;
DHT dht(DHT_PIN, DHT22);
WiFiClientSecure secureClient;
WiFiClient plainClient;
PubSubClient mqtt(secureClient);

// ------------------------------------------------------------------ utilities
String toHex(const uint8_t *data, size_t length) {
  static const char *digits = "0123456789abcdef";
  String out;
  out.reserve(length * 2);
  for (size_t i = 0; i < length; i++) {
    out += digits[(data[i] >> 4) & 0x0F];
    out += digits[data[i] & 0x0F];
  }
  return out;
}

bool hexToBytes(const String &hex, uint8_t *out, size_t outLength) {
  if (hex.length() != outLength * 2) return false;
  for (size_t i = 0; i < outLength; i++) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], 0};
    char *end = nullptr;
    long value = strtol(pair, &end, 16);
    if (end != pair + 2) return false;
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}

String sha256Hex(const String &canonical) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(kReadingDomain), strlen(kReadingDomain));
  mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(canonical.c_str()), canonical.length());
  uint8_t digest[32];
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
  return toHex(digest, sizeof(digest));
}

String hmacSha256Hex(const uint8_t *key, size_t keyLength, const String &canonical, const uint8_t *digest) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLength);
  mbedtls_md_hmac_update(&ctx, reinterpret_cast<const unsigned char *>(kReadingDomain), strlen(kReadingDomain));
  mbedtls_md_hmac_update(&ctx, digest, 32);
  uint8_t output[32];
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);
  return toHex(output, sizeof(output));
}

String isoNow() {
  time_t now = time(nullptr);
  struct tm utc;
  gmtime_r(&now, &utc);
  char base[24];
  strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &utc);
  char out[32];
  snprintf(out, sizeof(out), "%s.%03uZ", base, static_cast<unsigned>(millis() % 1000));
  return String(out);
}

String makeNonce() {
  char buffer[17];
  snprintf(buffer, sizeof(buffer), "%08x%08x", esp_random(), esp_random());
  return String(buffer);
}

// ------------------------------------------------------------------ hardware
void readGps(int32_t &latE7, int32_t &lonE7, int &fix) {
  uint32_t started = millis();
  while (millis() - started < GPS_WARMUP_MS) {
    while (gpsSerial.available() > 0) {
      gps.encode(gpsSerial.read());
    }
    delay(10);
  }
  if (gps.location.isValid() && gps.location.age() < 15000) {
    latE7 = static_cast<int32_t>(llround(gps.location.lat() * 1e7));
    lonE7 = static_cast<int32_t>(llround(gps.location.lng() * 1e7));
    fix = 1;
  } else {
    latE7 = 0;
    lonE7 = 0;
    fix = 0;
  }
}

bool readDht(int32_t &tempCenti, int32_t &humidityMilli) {
  for (int attempt = 0; attempt < 3; attempt++) {
    float temperature = dht.readTemperature();
    float humidity = dht.readHumidity();
    if (!isnan(temperature) && !isnan(humidity)) {
      tempCenti = static_cast<int32_t>(llround(temperature * 100.0f));
      humidityMilli = static_cast<int32_t>(llround(humidity * 1000.0f));
      return true;
    }
    delay(1200);
  }
  return false;
}

// ------------------------------------------------------------------- network
bool connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < 15000) {
    delay(250);
  }
  return WiFi.status() == WL_CONNECTED;
}

bool connectMqtt() {
  if (MQTT_USE_TLS) {
    secureClient.setCACert(MQTT_ROOT_CA);
    mqtt.setClient(secureClient);
  } else {
    mqtt.setClient(plainClient);
  }
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(768);
  String clientId = String("vchain-") + DEVICE_ID + "-" + String(esp_random(), HEX);
  bool ok;
  if (strlen(MQTT_USERNAME) > 0) {
    ok = mqtt.connect(clientId.c_str(), MQTT_USERNAME, MQTT_PASSWORD);
  } else {
    ok = mqtt.connect(clientId.c_str());
  }
  return ok;
}

bool waitForClock() {
  uint32_t started = millis();
  while (time(nullptr) < 1700000000 && millis() - started < 12000) {
    delay(200);
  }
  return time(nullptr) >= 1700000000;
}

// -------------------------------------------------------------------- publish
bool publishReading() {
  int32_t temperature = 0;
  int32_t humidity = 0;
  if (!readDht(temperature, humidity)) {
    Serial.println("[vchain] DHT22 read failed; refusing to publish");
    return false;
  }

  int32_t latE7 = 0;
  int32_t lonE7 = 0;
  int fix = 0;
  readGps(latE7, lonE7, fix);

  if (!waitForClock()) {
    Serial.println("[vchain] clock not synchronised; refusing to publish");
    return false;
  }

  vchain::ReadingPayload reading{
      DEVICE_ID,
      FIRMWARE_VERSION,
      fix,
      humidity,
      latE7,
      lonE7,
      std::string(isoNow().c_str()),
      std::string(makeNonce().c_str()),
      gSequence,
      temperature,
  };
  String canonical = vchain::canonicalPayload(reading).c_str();
  String digestHex = sha256Hex(canonical);

  uint8_t key[32];
  if (!hexToBytes(String(DEVICE_SECRET_HEX), key, sizeof(key))) {
    Serial.println("[vchain] DEVICE_SECRET_HEX must be 64 hex characters");
    return false;
  }
  uint8_t digestBytes[32];
  hexToBytes(digestHex, digestBytes, sizeof(digestBytes));
  String signatureHex = hmacSha256Hex(key, sizeof(key), canonical, digestBytes);

  String envelope = vchain::envelope(canonical.c_str(), digestHex.c_str(), signatureHex.c_str()).c_str();
  String topic = String("vaccine/") + DEVICE_ID + "/telemetry";

  if (!mqtt.connected() && !connectMqtt()) {
    Serial.println("[vchain] MQTT connection failed");
    return false;
  }
  bool published = mqtt.publish(topic.c_str(), envelope.c_str(), false);
  mqtt.loop();
  delay(150);
  mqtt.disconnect();

  if (published) {
    gSequence++;
    Serial.printf("[vchain] seq=%u temp=%.2fC rh=%.2f%% gps=%d digest=%s\n", reading.seq,
                  temperature / 100.0, humidity / 1000.0, fix, digestHex.c_str());
  } else {
    Serial.println("[vchain] publish failed");
  }
  return published;
}

void goToSleep() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  mqtt.disconnect();
  Serial.flush();
  esp_sleep_enable_timer_wakeup(static_cast<uint64_t>(READING_INTERVAL_S) * 1000000ULL);
  esp_deep_sleep_start();
}

void setup() {
  Serial.begin(115200);
  delay(50);
  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, LOW);
  dht.begin();
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  gWakeCount++;

  if (!connectWiFi()) {
    Serial.println("[vchain] Wi-Fi unavailable; sleeping");
    goToSleep();
  }

  bool published = false;
  for (int attempt = 0; attempt < 3 && !published; attempt++) {
    published = publishReading();
    if (!published) delay(500);
  }
  digitalWrite(STATUS_LED_PIN, published ? HIGH : LOW);
  goToSleep();
}

void loop() {
  // Deep sleep means loop() is never reached; kept for completeness.
}
