# ESP32 vaccine-transport node

Firmware for the edge half of VChain: a battery-powered ESP32 that samples a
DHT22 and a NEO-6M GPS, signs each reading with HMAC-SHA256, publishes it over
MQTT and returns to deep sleep.

## Wiring

| Signal | ESP32 pin | Notes |
| --- | --- | --- |
| DHT22 data | GPIO 4 | 10 kΩ pull-up to 3V3 |
| DHT22 VCC / GND | 3V3 / GND | 100 nF decoupling recommended |
| GPS TX → ESP32 RX | GPIO 16 | NEO-6M TX, 9600 baud |
| GPS RX ← ESP32 TX | GPIO 17 | optional |
| GPS VCC / GND | 3V3 / GND | GPS draws ~45 mA while acquiring |
| Status LED | GPIO 2 | on-board LED, publish success indicator |

Power the node from a 3.7 V Li-ion cell through a low-quiescent-current LDO.
The reference power model in `vchain/metrics.py` assumes a 2500 mAh cell,
120 mA active draw, 50 µA sleep draw, a 4 s wake window and a 30 s duty cycle.

## Libraries

Install through the Arduino Library Manager:

- **DHT sensor library** (Adafruit) + **Adafruit Unified Sensor**
- **TinyGPSPlus** (Mikal Hart)
- **PubSubClient** (Nick O'Leary)

Board package: **esp32 by Espressif**. The sketch uses the bundled mbedTLS for
SHA-256 and HMAC, so no extra crypto library is required.

## Provisioning

1. Copy `config.h.example` to `secrets.h` and fill in Wi-Fi and broker details.
2. Derive the device key on the gateway host:

   ```bash
   VCHAIN_MASTER_SECRET=... python scripts/provision_device.py VX-001
   ```

3. Paste the 64-hex key into `DEVICE_SECRET_HEX`.
4. Flash the sketch. The sequence counter is kept in RTC memory so it survives
   deep sleep; it is reset only on power loss. If a node is re-flashed, reset
   the demo ledger or provision a new device id.

`secrets.h` is git-ignored. In production, store the key in NVS encrypted
storage or an ATECC608A secure element rather than a header file.

## What gets signed

The payload is fixed-point and canonically encoded, matching
`vchain/crypto.py` byte for byte:

```json
{"device_id":"VX-001","firmware":"1.0.0","gps_fix":1,"humidity_milli_pct":45250,"lat_e7":407128000,"lon_e7":-740059000,"measured_at":"2026-11-22T09:10:00.123Z","nonce":"a1b2c3d4e5f60718","seq":42,"temperature_centi_c":512}
```

- `digest = SHA-256("VCHAIN/reading/v1:" || canonical_payload)`
- `signature = HMAC-SHA256(device_key, "VCHAIN/reading/v1:" || digest_bytes)`
- envelope keys are sorted: `alg`, `digest`, `payload`, `signature`

`firmware/test/test_canonical.cpp` compiles the same encoder on a host; the
pytest suite compares its output with Python's `canonical_json`.

## MQTT

- Topic: `vaccine/<DEVICE_ID>/telemetry`
- Envelope is published as a UTF-8 JSON string.
- `PubSubClient::publish` uses QoS 0. The gateway subscribes at QoS 1 and
  de-duplicates by digest, so a lost packet costs one sample rather than
  corrupting the record. For QoS 1/2 on the device, use `MQTT` (lwmqtt) or
  `AsyncMqttClient` and keep the same payload.
- Set `MQTT_USE_TLS 1` and paste the broker CA into `MQTT_ROOT_CA` for TLS on
  port 8883. Never ship a production fleet with plaintext MQTT.

## Power profile

| Phase | Current | Duration |
| --- | --- | --- |
| Wake, DHT22 + GPS acquire | ~120 mA | ~4 s |
| SHA-256 + HMAC + MQTT publish | ~120 mA | included above |
| Deep sleep | ~50 µA | ~26 s |

Average ≈ 16 mA, so a 2500 mAh cell derated to 85 % lasts ≈ 130 h, well past
the 72 h requirement. Increase `READING_INTERVAL_S` or reduce `GPS_WARMUP_MS`
to extend it further. The dashboard reports the model with the project defaults
(30 s interval, 2.5 s GPS warm-up).

## Failure behaviour

- DHT22 read failure → no publish, retry up to three times, then sleep.
- No GPS fix → publishes `gps_fix: 0` with zero coordinates; the policy engine
  raises `GPS_NO_FIX` and the reading is still anchored.
- Clock not synchronised → no publish (a bogus timestamp would be rejected).
- MQTT unavailable → retries, then sleeps and tries again next cycle.
