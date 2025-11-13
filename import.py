# import.py — PURE PYTHON QR FIXED
import subprocess
import sys
import importlib

REQ = {
    "streamlit": "1.28.0",
    "cryptography": "42.0.0",
    "qrcode": "7.4",
    "pillow": "10.0"
    #"qrcodeutil": "1.0.0",  # ← PURE PYTHON QR DECODER
    #"opencv-python": "4.8"  # Keep for image prep if needed
}

def install(pkg, ver):
    subprocess.check_call([sys.executable, "-m", "pip", "install", f"{pkg}>={ver}", "--quiet"])

def check():
    print("[ChainChat] Locking down dependencies...")
    for pkg, ver in REQ.items():
        try:
            importlib.import_module(pkg.replace("-", "_"))
            print(f"[OK] {pkg}")
        except ImportError:
            print(f"[INSTALL] {pkg} >= {ver}")
            install(pkg, ver)

if __name__ == "__main__":
    check()