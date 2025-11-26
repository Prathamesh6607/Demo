import os
import sys
import subprocess
import shutil

REQUIRED_PY_PACKAGES = [
    'flask', 'pandas', 'requests', 'nmap', 'scapy', 'python-dotenv'
]
REQUIRED_DIRS = ['scans', 'uploads']


def check_and_install_packages():
    import importlib
    for pkg in REQUIRED_PY_PACKAGES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            print(f"[INFO] Installing missing package: {pkg}")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])


def check_nmap():
    nmap_path = shutil.which('nmap')
    if nmap_path:
        print(f"[OK] nmap found at: {nmap_path}")
        return True
    print("[ERROR] nmap is not installed or not in PATH.")
    print("Please install nmap manually:")
    print("- Windows: Download from https://nmap.org/download.html#windows and add to PATH")
    print("- Linux: sudo apt install nmap or sudo yum install nmap")
    return False


def ensure_directories():
    for d in REQUIRED_DIRS:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"[INFO] Created directory: {d}")
        else:
            print(f"[OK] Directory exists: {d}")
        # Check write permission
        try:
            testfile = os.path.join(d, 'test_write.tmp')
            with open(testfile, 'w') as f:
                f.write('test')
            os.remove(testfile)
            print(f"[OK] Write permission for: {d}")
        except Exception as e:
            print(f"[ERROR] No write permission for {d}: {e}")


def run_test_scan():
    try:
        from utils.bluetooth_scanner import BluetoothScanner
        scanner = BluetoothScanner()
        result = scanner.scan_bluetooth(duration=1)
        if 'devices' in result:
            print(f"[OK] Bluetooth scan simulation: {len(result['devices'])} devices found.")
        else:
            print("[WARN] Bluetooth scan simulation failed.")
    except Exception as e:
        print(f"[ERROR] Bluetooth scan test failed: {e}")

    try:
        from utils.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        progress = scanner.get_scan_progress()
        print(f"[OK] Network scanner initialized. Status: {progress['status']}")
    except Exception as e:
        print(f"[ERROR] Network scanner test failed: {e}")


def main():
    print("--- IoT NIST Monitor Automated Setup ---")
    check_and_install_packages()
    check_nmap()
    ensure_directories()
    run_test_scan()
    print("--- Setup Complete ---")

if __name__ == "__main__":
    main()
