"""Print the per-device HMAC key that must be provisioned into the ESP32 NVS.

Usage: python scripts/provision_device.py VX-001
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vchain.crypto import derive_device_key  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Derive an ESP32 device signing key")
    parser.add_argument("device_id", help="e.g. VX-001")
    parser.add_argument(
        "--master",
        default=os.environ.get("VCHAIN_MASTER_SECRET"),
        help="master secret (defaults to $VCHAIN_MASTER_SECRET)",
    )
    args = parser.parse_args()
    if not args.master:
        parser.error("set VCHAIN_MASTER_SECRET or pass --master")
    key = derive_device_key(args.master, args.device_id)
    print(f"device_id:  {args.device_id}")
    print(f"key (hex):  {key}")
    print()
    print("Add to firmware/vaccine_node/secrets.h:")
    print(f'#define DEVICE_SECRET_HEX "{key}"')


if __name__ == "__main__":
    main()
