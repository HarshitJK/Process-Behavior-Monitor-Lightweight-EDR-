"""
Attack Simulation Script 2: Ransomware Behavior Simulator
=========================================================
Creates, modifies, renames, and deletes many files very rapidly to mimic
the file-system patterns of a ransomware encryption campaign.

This should trigger the Lightweight EDR's FileMonitor:
  [CRITICAL] Ransomware-like file activity detected
  Events: N changes within T seconds

Usage (in WSL / Linux terminal):
  python attack_simulation/ransomware_simulation.py
  python attack_simulation/ransomware_simulation.py --files 30 --delay 0

IMPORTANT:
  Run the EDR first in a separate terminal AND ensure it is monitoring
  the same directory (EDRConfig.MONITOR_DIRECTORY = "testing_malware").
"""

import argparse
import os
import sys
import time
import random
import string

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import EDRConfig
    TARGET_DIR = EDRConfig.MONITOR_DIRECTORY
    THRESHOLD = EDRConfig.FILE_EVENT_THRESHOLD
    WINDOW = EDRConfig.TIME_WINDOW
except ImportError:
    TARGET_DIR = "testing_malware"
    THRESHOLD = 10
    WINDOW = 5.0


def random_content(size: int = 512) -> bytes:
    """Generate pseudo-random bytes to simulate encrypted file content."""
    return bytes(random.randint(0, 255) for _ in range(size))


def simulate_ransomware(target_dir: str, num_files: int, delay: float):
    """
    Phase 1 – CREATE files (simulate target acquisition)
    Phase 2 – MODIFY files (simulate encryption-in-place)
    Phase 3 – RENAME files with .encrypted extension (simulate renaming)
    Phase 4 – DELETE originals (simulate cleanup / ransom note only)
    """
    sim_dir = os.path.join(target_dir, "ransomware_sim")
    os.makedirs(sim_dir, exist_ok=True)

    created_files = []
    renamed_files = []

    print(f"\n[Phase 1] Creating {num_files} target files …")
    for i in range(num_files):
        fname = f"document_{i:04d}.txt"
        fpath = os.path.join(sim_dir, fname)
        with open(fpath, "w") as f:
            f.write(f"Sensitive data file #{i}\n" * 10)
        created_files.append(fpath)
        if delay > 0:
            time.sleep(delay)
        print(f"  [+] Created: {fname}")

    print(f"\n[Phase 2] Modifying (encrypting) {num_files} files …")
    for fpath in created_files:
        with open(fpath, "wb") as f:
            f.write(random_content(1024))
        if delay > 0:
            time.sleep(delay)
        print(f"  [~] Modified: {os.path.basename(fpath)}")

    print(f"\n[Phase 3] Renaming files to .encrypted …")
    for fpath in created_files:
        new_path = fpath + ".encrypted"
        os.rename(fpath, new_path)
        renamed_files.append(new_path)
        if delay > 0:
            time.sleep(delay)
        print(f"  [>] Renamed: {os.path.basename(fpath)} → {os.path.basename(new_path)}")

    print(f"\n[Phase 4] Deleting encrypted files …")
    for fpath in renamed_files:
        os.remove(fpath)
        if delay > 0:
            time.sleep(delay)
        print(f"  [-] Deleted: {os.path.basename(fpath)}")

    # Write ransom note
    note_path = os.path.join(sim_dir, "README_YOUR_FILES_ARE_ENCRYPTED.txt")
    with open(note_path, "w") as f:
        f.write(
            "YOUR FILES HAVE BEEN ENCRYPTED!\n"
            "This is a SIMULATION for educational purposes only.\n"
            "No actual damage was done.\n"
        )
    print(f"\n  [!] Ransom note written: {note_path}")

    # Cleanup simulation directory
    time.sleep(2)
    try:
        os.remove(note_path)
        os.rmdir(sim_dir)
        print("  [cleanup] Simulation directory removed.")
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Behavior Simulator – triggers EDR file alerts"
    )
    parser.add_argument(
        "--files", type=int, default=20,
        help=f"Number of files to create (default: 20; EDR threshold: {THRESHOLD})"
    )
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Delay in seconds between each file operation (default: 0 = no delay)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  RANSOMWARE SIMULATION – Lightweight EDR Attack Simulation")
    print("=" * 60)
    print(f"  Target directory  : {os.path.abspath(TARGET_DIR)}")
    print(f"  Files to create   : {args.files}")
    print(f"  Delay per op      : {args.delay}s")
    print(f"  EDR threshold     : {THRESHOLD} events / {WINDOW}s")
    print("=" * 60)
    print(
        f"\n[*] Starting ransomware simulation (4 phases) …\n"
        f"[*] EDR should trigger CRITICAL alert after {THRESHOLD} events!\n"
    )

    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR, exist_ok=True)
        print(f"[*] Created target directory: {TARGET_DIR}")

    try:
        simulate_ransomware(TARGET_DIR, args.files, args.delay)
    except KeyboardInterrupt:
        print("\n[!] Simulation interrupted.")

    print("\n[✓] Ransomware simulation complete.")
    print("    Check the EDR terminal for [CRITICAL] file-activity alerts.")


if __name__ == "__main__":
    main()
