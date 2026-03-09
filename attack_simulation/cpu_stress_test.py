"""
Attack Simulation Script 1: CPU Stress Test
===========================================
Simulates a process consuming abnormally high CPU for an extended period.
This should trigger the Lightweight EDR's:
  - Rule A: High CPU usage (WARNING)
  - Rule C: Sustained high CPU for N consecutive checks (CRITICAL → auto-terminate)

Usage (in WSL / Linux terminal):
  python attack_simulation/cpu_stress_test.py
  python attack_simulation/cpu_stress_test.py --duration 30 --cores 2

IMPORTANT:
  Run the EDR first in a separate terminal:
    python main.py --no-terminate    # alert-only (safe for demo)
    python main.py                   # with auto-terminate
"""

import argparse
import time
import threading
import os
import sys

# Make sure we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import EDRConfig
    THRESHOLD = EDRConfig.CPU_THRESHOLD
    CONSECUTIVE = EDRConfig.CPU_CONSECUTIVE_CHECKS
    SCAN_INTERVAL = EDRConfig.SCAN_INTERVAL
except ImportError:
    THRESHOLD = 80.0
    CONSECUTIVE = 5
    SCAN_INTERVAL = 2.0


def cpu_burn(stop_event: threading.Event):
    """Tight computation loop to saturate a CPU core."""
    while not stop_event.is_set():
        _ = sum(i * i for i in range(100_000))


def main():
    parser = argparse.ArgumentParser(
        description="CPU Stress Simulator – triggers EDR CPU alerts"
    )
    parser.add_argument(
        "--duration", type=int, default=30,
        help="Seconds to run the stress test (default: 30)"
    )
    parser.add_argument(
        "--cores", type=int, default=1,
        help="Number of CPU cores to stress (default: 1)"
    )
    args = parser.parse_args()

    # Estimated time before EDR triggers CRITICAL
    estimated_trigger = CONSECUTIVE * SCAN_INTERVAL

    print("=" * 60)
    print("  CPU STRESS TEST – Lightweight EDR Attack Simulation")
    print("=" * 60)
    print(f"  PID             : {os.getpid()}")
    print(f"  Duration        : {args.duration}s")
    print(f"  CPU cores       : {args.cores}")
    print(f"  EDR threshold   : {THRESHOLD}%")
    print(f"  EDR consecutive : {CONSECUTIVE} checks")
    print(f"  Expected alert  : ~{estimated_trigger:.0f}s after start")
    print("=" * 60)
    print("\n[*] Starting CPU stress …")
    print("[*] Watch the EDR terminal for [WARNING] and [CRITICAL] alerts!\n")

    stop = threading.Event()
    threads = [
        threading.Thread(target=cpu_burn, args=(stop,), daemon=True)
        for _ in range(args.cores)
    ]

    for t in threads:
        t.start()

    try:
        for elapsed in range(args.duration):
            time.sleep(1)
            bar = "#" * (elapsed + 1) + "-" * (args.duration - elapsed - 1)
            pct = int((elapsed + 1) / args.duration * 100)
            print(f"\r  [{bar}] {pct:3d}%  {elapsed+1:3d}/{args.duration}s", end="", flush=True)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=1)

    print("\n\n[✓] CPU stress test complete.")
    print("    Check the EDR terminal – it should have logged a CRITICAL alert.")


if __name__ == "__main__":
    main()
