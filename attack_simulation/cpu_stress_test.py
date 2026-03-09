"""
Attack Simulation: CPU Stress Test
Triggers EDR Rule A (High CPU → WARNING) and Rule C (Sustained → CRITICAL).

Issue 5 fix:
  - Uses multiprocessing so each worker is a SEPARATE process visible to psutil
  - Each worker runs a genuine 10-million-iteration inner loop
  - Workers all start simultaneously to guarantee > 90% CPU

Usage:
  python attack_simulation/cpu_stress_test.py
  python attack_simulation/cpu_stress_test.py --duration 45 --workers 4
"""

import argparse
import multiprocessing
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import EDRConfig
    THRESHOLD   = EDRConfig.CPU_THRESHOLD
    CONSECUTIVE = EDRConfig.CPU_CONSECUTIVE_CHECKS
    INTERVAL    = EDRConfig.SCAN_INTERVAL
except ImportError:
    THRESHOLD   = 80.0
    CONSECUTIVE = 3
    INTERVAL    = 2.0


# ---------------------------------------------------------------------------
# Worker (runs as separate process – fully visible to psutil)
# ---------------------------------------------------------------------------

def _cpu_worker(duration: int):
    """Burn CPU in a tight loop for `duration` seconds."""
    deadline = time.time() + duration
    while time.time() < deadline:
        x = 0
        for i in range(10_000_000):
            x += i * i    # real arithmetic, can't be optimised away
    # Done – exit naturally so the OS reclaims it


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CPU Stress Test – triggers EDR CPU alerts"
    )
    parser.add_argument("--duration", type=int, default=30,
                        help="Seconds to run (default: 30)")
    parser.add_argument("--workers", type=int,
                        default=max(1, multiprocessing.cpu_count()),
                        help="Parallel worker processes (default: all cores)")
    args = parser.parse_args()

    estimated_trigger = CONSECUTIVE * INTERVAL

    print("=" * 60)
    print("  CPU STRESS TEST – Lightweight EDR Attack Simulation")
    print("=" * 60)
    print(f"  Main PID         : {os.getpid()}")
    print(f"  Worker processes : {args.workers}")
    print(f"  Duration         : {args.duration}s")
    print(f"  EDR CPU Warning  : {THRESHOLD}%")
    print(f"  EDR Consecutive  : {CONSECUTIVE} scans  (~{estimated_trigger:.0f}s to CRITICAL)")
    print("=" * 60)
    print("\n[*] Spawning worker processes …")
    print("[*] Watch the EDR terminal for [WARNING] then [CRITICAL] alerts!\n")

    workers = []
    for _ in range(args.workers):
        p = multiprocessing.Process(target=_cpu_worker, args=(args.duration,),
                                    daemon=True)
        p.start()
        workers.append(p)
        print(f"  [+] Worker PID {p.pid} started")

    print()
    try:
        for elapsed in range(args.duration):
            time.sleep(1)
            alive = sum(1 for w in workers if w.is_alive())
            bar   = "█" * (elapsed + 1) + "░" * (args.duration - elapsed - 1)
            print(f"\r  [{bar}] {elapsed + 1:3d}/{args.duration}s  ({alive} workers running)",
                  end="", flush=True)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    finally:
        for w in workers:
            if w.is_alive():
                w.terminate()
        for w in workers:
            w.join(timeout=2)

    print("\n\n[✓] CPU stress test complete.")
    print("    Check the EDR terminal – should show WARNING + CRITICAL alerts.")


if __name__ == "__main__":
    # Required on Windows for multiprocessing
    multiprocessing.freeze_support()
    main()
