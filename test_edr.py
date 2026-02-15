"""
Test Script for Enhanced EDR Features
Demonstrates the new detection capabilities.
"""

import psutil
import time
import os
from config import EDRConfig

def test_cpu_stress():
    """
    Test CPU stress detection.
    This will trigger an alert after consecutive high CPU checks.
    """
    print("\n=== Testing CPU Stress Detection ===")
    print(f"This will consume CPU for {EDRConfig.CPU_CONSECUTIVE_CHECKS + 2} seconds")
    print("The EDR should detect sustained high CPU usage.\n")
    
    start_time = time.time()
    duration = EDRConfig.CPU_CONSECUTIVE_CHECKS + 2
    
    # CPU-intensive loop
    while time.time() - start_time < duration:
        # Busy loop to consume CPU
        _ = sum(i**2 for i in range(10000))
    
    print("CPU stress test completed.")

def test_memory_allocation():
    """
    Test memory allocation detection.
    WARNING: This allocates significant memory!
    """
    print("\n=== Testing Memory Allocation Detection ===")
    print("Allocating memory in chunks...")
    
    data = []
    try:
        for i in range(100):
            # Allocate 100MB chunks
            chunk = ' ' * (100 * 1024 * 1024)
            data.append(chunk)
            
            current_process = psutil.Process()
            mem_percent = current_process.memory_percent()
            print(f"Allocated {(i+1) * 100}MB - Memory usage: {mem_percent:.2f}%")
            
            time.sleep(0.5)
            
            if mem_percent > 50:
                print("\nReached 50% memory usage - stopping allocation")
                break
    except MemoryError:
        print("Memory allocation limit reached")
    finally:
        # Clean up
        del data
        print("Memory released")

def test_file_activity():
    """
    Test ransomware-like file activity detection.
    """
    print("\n=== Testing File Activity Detection ===")
    print(f"Creating {EDRConfig.FILE_CHANGE_THRESHOLD + 5} files rapidly...")
    
    test_dir = os.path.join(EDRConfig.MONITOR_DIRECTORY, "test_files")
    os.makedirs(test_dir, exist_ok=True)
    
    # Create files rapidly
    for i in range(EDRConfig.FILE_CHANGE_THRESHOLD + 5):
        filepath = os.path.join(test_dir, f"test_file_{i}.txt")
        with open(filepath, 'w') as f:
            f.write(f"Test file {i}\n")
        print(f"Created file {i+1}")
    
    print("\nFile creation completed.")
    print("The EDR should detect ransomware-like activity.")
    
    # Cleanup
    time.sleep(2)
    for i in range(EDRConfig.FILE_CHANGE_THRESHOLD + 5):
        filepath = os.path.join(test_dir, f"test_file_{i}.txt")
        if os.path.exists(filepath):
            os.remove(filepath)
    
    if os.path.exists(test_dir):
        os.rmdir(test_dir)
    
    print("Test files cleaned up.")

def display_current_config():
    """Display current EDR configuration."""
    print("\n" + "="*60)
    print("CURRENT EDR CONFIGURATION")
    print("="*60)
    print(f"CPU Threshold: {EDRConfig.CPU_THRESHOLD}%")
    print(f"Consecutive CPU Checks Required: {EDRConfig.CPU_CONSECUTIVE_CHECKS}")
    print(f"Memory Threshold: {EDRConfig.MEMORY_THRESHOLD}%")
    print(f"Combined CPU Threshold: {EDRConfig.COMBINED_CPU_THRESHOLD}%")
    print(f"Alert Cooldown: {EDRConfig.ALERT_COOLDOWN_SECONDS} seconds")
    print(f"Auto-Terminate: {EDRConfig.AUTO_TERMINATE}")
    print(f"File Change Threshold: {EDRConfig.FILE_CHANGE_THRESHOLD} changes")
    print(f"File Time Window: {EDRConfig.FILE_TIME_WINDOW} seconds")
    print("="*60 + "\n")

def main():
    """Main test menu."""
    display_current_config()
    
    print("EDR Test Suite")
    print("-" * 40)
    print("1. Test CPU Stress Detection")
    print("2. Test Memory Allocation Detection (WARNING: Uses lots of RAM)")
    print("3. Test File Activity Detection")
    print("4. Display Configuration")
    print("0. Exit")
    print("-" * 40)
    
    while True:
        choice = input("\nSelect test (0-4): ").strip()
        
        if choice == '1':
            print("\nWARNING: Make sure EDR is running in another terminal!")
            confirm = input("Continue? (y/n): ").strip().lower()
            if confirm == 'y':
                test_cpu_stress()
        
        elif choice == '2':
            print("\nWARNING: This will allocate significant memory!")
            print("Make sure EDR is running in another terminal!")
            confirm = input("Continue? (y/n): ").strip().lower()
            if confirm == 'y':
                test_memory_allocation()
        
        elif choice == '3':
            print("\nWARNING: Make sure EDR is running in another terminal!")
            confirm = input("Continue? (y/n): ").strip().lower()
            if confirm == 'y':
                test_file_activity()
        
        elif choice == '4':
            display_current_config()
        
        elif choice == '0':
            print("\nExiting test suite.")
            break
        
        else:
            print("Invalid choice. Please select 0-4.")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("LIGHTWEIGHT EDR - TEST SUITE")
    print("="*60)
    print("\nIMPORTANT:")
    print("1. Run the EDR system first: python main.py --gui")
    print("2. Then run this test script in a separate terminal")
    print("3. Watch the EDR detect and respond to threats!")
    print("="*60)
    
    main()
