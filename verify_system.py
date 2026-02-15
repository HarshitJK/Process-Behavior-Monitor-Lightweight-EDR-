#!/usr/bin/env python3
"""
Quick Verification Script
Tests that all modules load correctly and configuration is valid.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("="*60)
    print("TESTING MODULE IMPORTS")
    print("="*60)
    
    try:
        print("\n[1/5] Testing config...")
        from config import EDRConfig
        print(f"  ✓ Config loaded")
        print(f"    - Memory WARNING threshold: {EDRConfig.MEMORY_WARNING_THRESHOLD}%")
        print(f"    - Memory CRITICAL threshold: {EDRConfig.MEMORY_CRITICAL_THRESHOLD}%")
        print(f"    - Memory COMBINED threshold: {EDRConfig.MEMORY_THRESHOLD}%")
        print(f"    - CPU threshold: {EDRConfig.CPU_THRESHOLD}%")
        print(f"    - Debug mode: {EDRConfig.DEBUG_MODE}")
        
        print("\n[2/5] Testing scanner...")
        from scanner.process_scanner import ProcessScanner
        print("  ✓ Scanner module loaded")
        
        print("\n[3/5] Testing analyzer...")
        from analyzer.behavior_analyzer import BehaviorAnalyzer
        analyzer = BehaviorAnalyzer()
        print("  ✓ Analyzer module loaded")
        print(f"    - Memory WARNING threshold: {analyzer.memory_warning_threshold}%")
        print(f"    - Memory CRITICAL threshold: {analyzer.memory_critical_threshold}%")
        
        print("\n[4/5] Testing responder...")
        from response.responder import Responder
        print("  ✓ Responder module loaded")
        
        print("\n[5/5] Testing file monitor...")
        from monitor.file_monitor import FileMonitor
        print("  ✓ File monitor module loaded")
        
        print("\n" + "="*60)
        print("✓ ALL MODULES LOADED SUCCESSFULLY")
        print("="*60)
        
        return True
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_detection_logic():
    """Test detection logic with sample data."""
    print("\n" + "="*60)
    print("TESTING DETECTION LOGIC")
    print("="*60)
    
    try:
        from analyzer.behavior_analyzer import BehaviorAnalyzer
        from config import EDRConfig
        
        analyzer = BehaviorAnalyzer()
        
        # Test case 1: High memory (should trigger WARNING)
        print("\n[TEST 1] Memory 65% (should trigger WARNING)")
        result = analyzer.analyze(
            process={'pid': 1234, 'name': 'test', 'cpu_percent': 10.0, 'memory_percent': 65.0},
            history=[]
        )
        print(f"  Suspicious: {result['suspicious']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Reasons: {result['reasons']}")
        assert result['suspicious'] == True, "Should detect high memory"
        assert result['severity'] == 'WARNING', "Should be WARNING severity"
        print("  ✓ PASS")
        
        # Test case 2: Very high memory (should trigger CRITICAL)
        print("\n[TEST 2] Memory 85% (should trigger CRITICAL)")
        analyzer.reset_cooldown(1235)
        result = analyzer.analyze(
            process={'pid': 1235, 'name': 'test2', 'cpu_percent': 10.0, 'memory_percent': 85.0},
            history=[]
        )
        print(f"  Suspicious: {result['suspicious']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Reasons: {result['reasons']}")
        assert result['suspicious'] == True, "Should detect critical memory"
        assert result['severity'] == 'CRITICAL', "Should be CRITICAL severity"
        print("  ✓ PASS")
        
        # Test case 3: Normal usage (should be INFO)
        print("\n[TEST 3] Memory 40%, CPU 30% (should be INFO)")
        result = analyzer.analyze(
            process={'pid': 1236, 'name': 'test3', 'cpu_percent': 30.0, 'memory_percent': 40.0},
            history=[]
        )
        print(f"  Suspicious: {result['suspicious']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Reasons: {result['reasons']}")
        assert result['suspicious'] == False, "Should not detect normal usage"
        print("  ✓ PASS")
        
        print("\n" + "="*60)
        print("✓ ALL DETECTION TESTS PASSED")
        print("="*60)
        
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("EDR SYSTEM VERIFICATION")
    print("="*60)
    
    # Test imports
    if not test_imports():
        print("\n✗ Import tests failed!")
        sys.exit(1)
    
    # Test detection logic
    if not test_detection_logic():
        print("\n✗ Detection tests failed!")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("✓✓✓ ALL TESTS PASSED ✓✓✓")
    print("="*60)
    print("\nYour EDR system is ready to use!")
    print("\nTo start the EDR:")
    print("  python main.py --gui")
    print("\nTo test with attack simulations:")
    print("  cd testing_malware")
    print("  python run_tests.py")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
